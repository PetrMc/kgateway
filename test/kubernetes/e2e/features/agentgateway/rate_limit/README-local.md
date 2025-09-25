# Test steps

## Create your local environment

1. Deploy kind cluster with agentgateway support:

```bash
make run HELM_ADDITIONAL_VALUES=test/kubernetes/e2e/tests/manifests/agent-gateway-integration.yaml
```

2. Define your OPENAI_API_KEY env variable

```bash
export OPENAI_API_KEY=<your key usually starts wtih "sk-">
```

3. Create the secret with your token:

```bash
kubectl create secret generic openai-secret   --from-literal=Authorization="Bearer ${OPENAI_API_KEY}"
```

4. Now apply the rest of the configuration:

Deploy gateway:

```bash
kubectl apply -f test/kubernetes/e2e/features/agentgateway/rate_limit/testdata/common.yaml
```

Deploy LLM config:

```bash
kubectl apply -f test/kubernetes/e2e/features/agentgateway/rate_limit/testdata/local-tokens-rl.yaml
```

## Test the configuration:

1. Validate config of the dataplane

- check policies:

```bash
kubectl get pods -l app.kubernetes.io/name=super-gateway -o jsonpath='{.items[0].metadata.name}' | xargs -I {} kubectl port-forward pod/{} 15000:15000 & sleep 2 && curl -s localhost:15000/config_dump | jq '.policies' && kill %1
```

should have two - `Rate Limit` and `Authorization`.

```output
[
  {
    "name": "auth-default/openai-backend-backend",
    "target": {
      "subBackend": "default/openai-backend/backend"
    },
    "policy": {
      "backendAuth": {
        "key": "<redacted>"
      }
    }
  },
  {
    "name": "trafficpolicy/default/token-rate-limit/super-gateway:rl-local",
    "target": {
      "gateway": "default/super-gateway"
    },
    "policy": {
      "localRateLimit": [
        {
          "maxTokens": 50,
          "tokensPerFill": 10,
          "fillInterval": "10s",
          "type": "tokens"
        }
      ]
    }
  }
]
```

-  fetch backends:

```bash
kubectl get pods -l app.kubernetes.io/name=super-gateway -o jsonpath='{.items[0].metadata.name}' | xargs -I {} kubectl port-forward pod/{} 15000:15000 & sleep 2 && curl -s localhost:15000/config_dump | jq '.backends' && kill %1
```

you should see OpenAI backend in the output:

```output
[
  {
    "ai": {
      "name": "default/openai-backend",
      "target": {
        "providers": [
          {
            "active": {
              "backend": {
                "endpoint": {
                  "name": "backend",
                  "provider": {
                    "openAI": {
                      "model": "gpt-3.5-turbo"
                    }
                  },
                  "hostOverride": null,
                  "pathOverride": null,
                  "tokenize": false
                },
                "info": {
                  "health": 1.0,
                  "request_latency": 0.0,
                  "pending_requests": 0,
                  "total_requests": 0,
                  "evicted_until": null
                }
              }
            },
            "rejected": {}
          }
        ]
      }
    }
  }
]
```

2. Test with curl:

- enable port forwarding for the agentgateway:

```bash
kubectl get pods -l app.kubernetes.io/name=super-gateway -o jsonpath='{.items[0].metadata.name}' | xargs -I {} kubectl port-forward pod/{} 8080:8080 &
```

- Send the single request:
```bash
curl -H "Host: ai.example.com" http://localhost:8080/v1/chat/completions -X POST -H "Content-Type: application/json" -d '{"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "Hi"}], "max_tokens": 5}' -w "Status: %{http_code}\n" -s
```
  if the setup is correct you should get 200:
```output
{"id":"chatcmpl-CJkcyOb2Aj9XjF9PZzpMxhjXTUzQH","choices":[{"index":0,"message":{"content":"Hello! How can I","role":"assistant"},"finish_reason":"length"}],"created":1758823504,"model":"gpt-3.5-turbo-0125","service_tier":"default","object":"chat.completion","usage":{"prompt_tokens":8,"completion_tokens":5,"total_tokens":13,"prompt_tokens_details":{"audio_tokens":0,"cached_tokens":0},"completion_tokens_details":{"accepted_prediction_tokens":0,"audio_tokens":0,"reasoning_tokens":0,"rejected_prediction_tokens":0}}}Status: 200
```

- Now confirm rate limiting by sending the repeating request:
```bash
for i in {1..10}; do echo "Request $i:"; curl -H "Host: ai.example.com" http://localhost:8080/v1/chat/completions -X POST -H "Content-Type: application/json" -d "{\"model\": \"gpt-3.5-turbo\", \"messages\": [{\"role\": \"user\", \"content\": \"Test message $i\"}], \"max_tokens\": 10}" -w "Status: %{http_code}\n" -s; sleep 1; done
```
After few succesful requests, the ratelimiting token count will be full and the request will get `429`:
```output
Request 1:
{"id":"chatcmpl-CJkgQi7YlLwVPU4rIOrp3FzNrTTj5","choices":[{"index":0,"message":{"content":"Hello! How can I assist you today?","role":"assistant"},"finish_reason":"stop"}],"created":1758823718,"model":"gpt-3.5-turbo-0125","service_tier":"default","object":"chat.completion","usage":{"prompt_tokens":11,"completion_tokens":9,"total_tokens":20,"prompt_tokens_details":{"audio_tokens":0,"cached_tokens":0},"completion_tokens_details":{"accepted_prediction_tokens":0,"audio_tokens":0,"reasoning_tokens":0,"rejected_prediction_tokens":0}}}Status: 200
Request 2:
{"id":"chatcmpl-CJkgScRhacVKpYuWNfdWIqgJ3DTnY","choices":[{"index":0,"message":{"content":"Hello! How can I assist you today?","role":"assistant"},"finish_reason":"stop"}],"created":1758823720,"model":"gpt-3.5-turbo-0125","service_tier":"default","object":"chat.completion","usage":{"prompt_tokens":11,"completion_tokens":9,"total_tokens":20,"prompt_tokens_details":{"audio_tokens":0,"cached_tokens":0},"completion_tokens_details":{"accepted_prediction_tokens":0,"audio_tokens":0,"reasoning_tokens":0,"rejected_prediction_tokens":0}}}Status: 200
Request 3:
{"id":"chatcmpl-CJkgUJVlR0H7RrTayHGpeVbVR5bp9","choices":[{"index":0,"message":{"content":"Hello! How can I assist you today?","role":"assistant"},"finish_reason":"stop"}],"created":1758823722,"model":"gpt-3.5-turbo-0125","service_tier":"default","object":"chat.completion","usage":{"prompt_tokens":11,"completion_tokens":9,"total_tokens":20,"prompt_tokens_details":{"audio_tokens":0,"cached_tokens":0},"completion_tokens_details":{"accepted_prediction_tokens":0,"audio_tokens":0,"reasoning_tokens":0,"rejected_prediction_tokens":0}}}Status: 200
Request 4:
{"id":"chatcmpl-CJkgVrRDlDE96oTNPud3p4k7CoN1e","choices":[{"index":0,"message":{"content":"Hello! How can I assist you today?","role":"assistant"},"finish_reason":"stop"}],"created":1758823723,"model":"gpt-3.5-turbo-0125","service_tier":"default","object":"chat.completion","usage":{"prompt_tokens":11,"completion_tokens":9,"total_tokens":20,"prompt_tokens_details":{"audio_tokens":0,"cached_tokens":0},"completion_tokens_details":{"accepted_prediction_tokens":0,"audio_tokens":0,"reasoning_tokens":0,"rejected_prediction_tokens":0}}}Status: 200
Request 5:
rate limit exceededStatus: 429
Request 6:
rate limit exceededStatus: 429
Request 7:
rate limit exceededStatus: 429
Request 8:
rate limit exceededStatus: 429
Request 9:
rate limit exceededStatus: 429
Request 10:
rate limit exceededStatus: 429
```






