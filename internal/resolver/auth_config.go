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
var ErrEitherDomainIdOrNameRequired = errors.New("one of either domain id or domain name is required")
var authValues = []struct {
	keyName  string
	required bool
	setter   func(*AuthConfig, string)
}{
	{
		keyName:  "tenantName",
		required: true,
		setter:   func(cfg *AuthConfig, value string) { cfg.authOpts.TenantName = value },
	},
	{
		keyName:  "tenantId",
		required: true,
		setter:   func(cfg *AuthConfig, value string) { cfg.authOpts.TenantID = value },
	},
	{
		keyName:  "domainName",
		required: false,
		setter:   func(cfg *AuthConfig, value string) { cfg.authOpts.DomainName = value },
	},
	{
		keyName:  "domainId",
		required: false,
		setter:   func(cfg *AuthConfig, value string) { cfg.authOpts.DomainID = value },
	},
	{
		keyName:  "username",
		required: true,
		setter:   func(cfg *AuthConfig, value string) { cfg.authOpts.Username = value },
	},
	{
		keyName:  "password",
		required: true,
		setter:   func(cfg *AuthConfig, value string) { cfg.authOpts.Password = value },
	},
	{
		keyName:  "identityEndpoint",
		required: true,
		setter:   func(cfg *AuthConfig, value string) { cfg.authOpts.IdentityEndpoint = value },
	},
	{
		keyName:  "region",
		required: true,
		setter:   func(cfg *AuthConfig, value string) { cfg.endpointOpts.Region = value },
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
		if !ok && val.required {
			return nil, fmt.Errorf("%w: %s", ErrMissingAuthValue, val.keyName)
		}
		val.setter(cfg, string(binaryContent))
	}

	if cfg.authOpts.DomainID == "" && cfg.authOpts.DomainName == "" {
		return nil, ErrEitherDomainIdOrNameRequired
	}

	//Always use DomainID over DomainName
	if cfg.authOpts.DomainID != "" {
		cfg.authOpts.DomainName = ""
	}

	cfg.authOpts.AllowReauth = true

	return cfg, nil
}
