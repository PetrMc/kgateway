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
kubectl apply -f test/kubernetes/e2e/features/agentgateway/rate_limit/testdata/global-tokens-rl.yaml
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
    "name": "trafficpolicy/default/global-token-rate-limit/super-gateway:rl-global",
    "target": {
      "gateway": "default/super-gateway"
    },
    "policy": {
      "remoteRateLimit": {
        "domain": "api-gateway",
        "target": {
          "service": {
            "name": "kgateway-test-extensions/ratelimit.kgateway-test-extensions.svc.cluster.local",
            "port": 8081
          }
        },
        "descriptors": [
          {
            "entries": [
              [
                "X-User-ID",
                "request.headers[\"x-user-id\"]"
              ]
            ],
            "type": "tokens"
          }
        ]
      }
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
                  "health": 0.6193845969999999,
                  "request_latency": 0.9883733316640071,
                  "pending_requests": 0,
                  "total_requests": 16,
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
for i in {1..8}; do 
  echo "Request $i:"; 
  curl -H "Host: ai.example.com" \
       -H "X-User-ID: user123" \
       http://localhost:8080/v1/chat/completions \
       -X POST -H "Content-Type: application/json" \
       -d '{"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "Test message '$i' with more content to generate more tokens"}], "max_tokens": 50}' \
       -w "Status: %{http_code}\n" -s; 
  sleep 2; 
done
```
After few succesful requests, the ratelimiting token count will be full and the request will get `429`:
```output
Request 1:
{"id":"chatcmpl-CJoAwRPQKGMp27jHGdEhOnsLMWVDZ","choices":[{"index":0,"message":{"content":"This is a sample message to test the functionality of the token generation. It is important to ensure that the tokens are being generated accurately and efficiently in order to improve the overall performance of the system. Let's see how many tokens are generated from this message","role":"assistant"},"finish_reason":"length"}],"created":1758837142,"model":"gpt-3.5-turbo-0125","service_tier":"default","object":"chat.completion","usage":{"prompt_tokens":18,"completion_tokens":50,"total_tokens":68,"prompt_tokens_details":{"audio_tokens":0,"cached_tokens":0},"completion_tokens_details":{"accepted_prediction_tokens":0,"audio_tokens":0,"reasoning_tokens":0,"rejected_prediction_tokens":0}}}Status: 200
Request 2:
{"id":"chatcmpl-CJoAzYOWOPdAr3NFIdLgDPTW4Om6K","choices":[{"index":0,"message":{"content":"Hello! Thank you for reaching out. I'm glad to assist you with any questions or concerns you may have. Let me know how I can help.","role":"assistant"},"finish_reason":"stop"}],"created":1758837145,"model":"gpt-3.5-turbo-0125","service_tier":"default","object":"chat.completion","usage":{"prompt_tokens":18,"completion_tokens":31,"total_tokens":49,"prompt_tokens_details":{"audio_tokens":0,"cached_tokens":0},"completion_tokens_details":{"accepted_prediction_tokens":0,"audio_tokens":0,"reasoning_tokens":0,"rejected_prediction_tokens":0}}}Status: 200
Request 3:
Status: 429
Request 4:
Status: 429
Request 5:
Status: 429
Request 6:
Status: 429
Request 7:
Status: 429
Request 8:
Status: 429
```

You can switch the user-x within minute interval to see this is per user.