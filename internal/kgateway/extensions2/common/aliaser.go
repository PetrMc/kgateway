package common

// NamespaceAliaser allows overriding a namespace (e.g., for peering logic).
type NamespaceAliaser interface {
	AliasNamespace(original string) string
}

type NoopAliaser struct{}

func (NoopAliaser) AliasNamespace(ns string) string {
	return ns
}
