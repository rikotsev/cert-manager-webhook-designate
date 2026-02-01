package resolver

import (
	"context"
	"errors"
	"fmt"

	"github.com/gophercloud/gophercloud/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type authConfigProvider struct {
	client kubernetes.Interface
}

type AuthConfig struct {
	authOpts     gophercloud.AuthOptions
	endpointOpts gophercloud.EndpointOpts
}

var ErrMissingAuthValue = errors.New("missing auth value")
var authValues = []struct {
	keyName string
	setter  func(*AuthConfig, string)
}{
	{
		keyName: "tenantName",
		setter:  func(cfg *AuthConfig, value string) { cfg.authOpts.TenantName = value },
	},
	{
		keyName: "tenantId",
		setter:  func(cfg *AuthConfig, value string) { cfg.authOpts.TenantID = value },
	},
	{
		keyName: "domainName",
		setter:  func(cfg *AuthConfig, value string) { cfg.authOpts.DomainName = value },
	},
	{
		keyName: "domainId",
		setter:  func(cfg *AuthConfig, value string) { cfg.authOpts.DomainID = value },
	},
	{
		keyName: "username",
		setter:  func(cfg *AuthConfig, value string) { cfg.authOpts.Username = value },
	},
	{
		keyName: "password",
		setter:  func(cfg *AuthConfig, value string) { cfg.authOpts.Password = value },
	},
	{
		keyName: "identityEndpoint",
		setter:  func(cfg *AuthConfig, value string) { cfg.authOpts.IdentityEndpoint = value },
	},
	{
		keyName: "region",
		setter:  func(cfg *AuthConfig, value string) { cfg.endpointOpts.Region = value },
	},
}

func (a *authConfigProvider) Get(ctx context.Context, namespace, secretName string) (*AuthConfig, error) {
	secret, err := a.client.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	cfg := new(AuthConfig)
	cfg.authOpts = gophercloud.AuthOptions{}

	for _, val := range authValues {
		binaryContent, ok := secret.Data[val.keyName]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrMissingAuthValue, val.keyName)
		}
		val.setter(cfg, string(binaryContent))
	}

	cfg.authOpts.AllowReauth = true

	return cfg, nil
}
