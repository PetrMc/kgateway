package common

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NamespaceAliaser allows overriding a namespace (e.g., for peering logic).
type NamespaceAliaser interface {
	AliasNamespace(obj metav1.Object) string
}

type NoopAliaser struct{}

func (NoopAliaser) AliasNamespace(obj metav1.Object) string {
	return obj.GetNamespace()
}
