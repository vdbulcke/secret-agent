package secretsmanager

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	"github.com/pkg/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vault "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/kubernetes"
)

var (
	DefaultVaultKVSecretPath = "kube/fr/secret"
	DefaultVaultAddress      = "http://vault-active.vault.svc.cluster.local:8200"
	DefaultVaultKubeRoleName = "fr-secret-agent"
	DefaultSecretKey         = "value"
	DefaultKVMount           = "secret"
)

// secretManagerVault container for GCP secret manager properties
type secretManagerVault struct {
	secretPath  string
	kvMount     string
	vaultClient *vault.Client
}

// newVault configures a new HC Vault secret manager client
func newVault(ctx context.Context, cfg *v1alpha1.AppConfig, rClient client.Client, cloudCredNS string) (*secretManagerVault, error) {

	vaultAddr := DefaultVaultAddress
	if cfg.VaultAddress != "" {
		vaultAddr = cfg.VaultAddress
	}

	vaultRole := DefaultVaultKubeRoleName
	if cfg.VaultKubeRole != "" {
		vaultRole = cfg.VaultKubeRole
	}

	vaultSecretPath := DefaultVaultKVSecretPath
	if cfg.VaultKVSecretPath != "" {
		vaultSecretPath = cfg.VaultKVSecretPath
	}

	vaultKVMount := DefaultKVMount
	if cfg.VaultKVMount != "" {
		vaultKVMount = cfg.VaultKVMount
	}

	// https://github.com/hashicorp/vault-examples/blob/main/examples/auth-methods/kubernetes/go/example.go
	// If set, the VAULT_ADDR environment variable will be the address that
	// your pod uses to communicate with Vault.
	config := vault.DefaultConfig() // modify for more granular configuration

	config.Address = vaultAddr

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("Vault: unable to initialize Vault client: %w", err)
	}

	// The service-account token will be read from the path where the token's
	// Kubernetes Secret is mounted. By default, Kubernetes will mount it to
	// /var/run/secrets/kubernetes.io/serviceaccount/token, but an administrator
	// may have configured it to be mounted elsewhere.
	// In that case, we'll use the option WithServiceAccountTokenPath to look
	// for the token there.
	k8sAuth, err := auth.NewKubernetesAuth(vaultRole)
	if err != nil {
		return nil, fmt.Errorf("Vault: unable to initialize Kubernetes auth method: %w", err)
	}

	authInfo, err := client.Auth().Login(ctx, k8sAuth)
	if err != nil {
		return nil, fmt.Errorf("Vault: unable to log in with Kubernetes auth: %w", err)
	}
	if authInfo == nil {
		return nil, fmt.Errorf("Vault: no auth info was returned after login")
	}

	return &secretManagerVault{
		vaultClient: client,
		secretPath:  vaultSecretPath,
		kvMount:     vaultKVMount,
	}, nil
}

// EnsureSecret ensures a single secret is stored in HC Vault
func (vm *secretManagerVault) EnsureSecret(ctx context.Context, secretName string, value []byte, secretType string) error {

	secretValue := vm.getSecretStrValue(value, secretType)

	payload := map[string]interface{}{
		DefaultSecretKey: secretValue,
		"secret_type":    secretType,
	}

	path := vm.getSecretPath(secretName)

	_, err := vm.vaultClient.KVv2(vm.kvMount).Put(ctx, path, payload)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil

}

// LoadSecret read secret from HC vault
func (vm *secretManagerVault) LoadSecret(ctx context.Context, secretName string, secretType string) ([]byte, error) {
	// get secret path
	path := vm.getSecretPath(secretName)

	// read secret from KV2 backend
	secret, err := vm.vaultClient.KVv2(vm.kvMount).Get(ctx, path)
	if err != nil {
		// return nil, errors.WithStack(err)
		// Secret not existing is fine, as that means we will create a new secret
		return []byte{}, nil
	}

	// extract secret key
	value, ok := secret.Data[DefaultSecretKey].(string)
	if !ok {
		// return nil, errors.WithStack(fmt.Errorf("vault: secret not found for %s", path))
		// Secret not existing is fine, as that means we will create a new secret
		return []byte{}, nil
	}

	// decode secret string according to type
	return vm.getSecretByteValue(value, secretType)

}

// CloseClient empty function to fulfil interface functions
func (vm *secretManagerVault) CloseClient() {}

// getSecretPath return full secret path
func (vm *secretManagerVault) getSecretPath(secretName string) string {
	return fmt.Sprintf("%s/%s", vm.secretPath, secretName)
}

// getSecretStrValue format bytes as string according to secret type
func (vm *secretManagerVault) getSecretStrValue(data []byte, secretType string) string {

	var value string

	switch secretType {
	case TypeKeystore:
		value = base64.StdEncoding.EncodeToString(data)
	case TypePEM:
		value = string(data)
	case TypePassword:
		value = string(data)
	default:
		value = base64.StdEncoding.EncodeToString(data)
	}

	return value
}

// getSecretByteValue format string as bytes  according to secret type
func (vm *secretManagerVault) getSecretByteValue(data, secretType string) ([]byte, error) {

	switch secretType {
	case TypeKeystore:
		return base64.StdEncoding.DecodeString(data)
	case TypePEM:
		return []byte(data), nil
	case TypePassword:
		return []byte(data), nil
	default:
		return base64.StdEncoding.DecodeString(data)
	}

}
