package resolver

import (
	"context"
	"errors"
	"testing"

	"github.com/gophercloud/gophercloud/v2"
	corev1 "k8s.io/api/core/v1"
	errors2 "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestAuthConfigProvider_Get(t *testing.T) {
	secretName := "openstackCredentials"
	namespace := "cert-manager"
	allKeys := map[string]string{
		"tenantName":       "testTenant",
		"tenantId":         "testTenantId",
		"domainName":       "testDomainName",
		"domainId":         "testDomainId",
		"username":         "john-doe",
		"password":         "secretpass",
		"identityEndpoint": "https://example.com",
		"region":           "RegionOne",
	}

	tcs := []struct {
		name             string
		secret           *corev1.Secret
		expectedAuthOpts *gophercloud.AuthOptions
		expectedNotFound bool
		expectedError    error
	}{
		{
			name:   "happy path",
			secret: dummySecret(secretName, namespace, allKeys),
			expectedAuthOpts: &gophercloud.AuthOptions{
				TenantName:       "testTenant",
				TenantID:         "testTenantId",
				DomainName:       "testDomainName",
				DomainID:         "testDomainId",
				Username:         "john-doe",
				Password:         "secretpass",
				IdentityEndpoint: "https://example.com",
				AllowReauth:      true,
			},
			expectedNotFound: false,
			expectedError:    nil,
		},
		{
			name:             "no secret",
			secret:           nil,
			expectedAuthOpts: nil,
			expectedNotFound: true,
			expectedError:    nil,
		},
		{
			name:             "wrong secret namespace",
			secret:           dummySecret(secretName, "default", map[string]string{}),
			expectedAuthOpts: nil,
			expectedNotFound: true,
			expectedError:    nil,
		},
		{
			name:             "wrong secret name",
			secret:           dummySecret("wrongName", namespace, map[string]string{}),
			expectedAuthOpts: nil,
			expectedNotFound: true,
			expectedError:    nil,
		},
		{
			name:             "missing tenant name",
			secret:           dummySecret(secretName, namespace, stripKey(allKeys, "tenantName")),
			expectedAuthOpts: nil,
			expectedNotFound: false,
			expectedError:    ErrMissingAuthValue,
		},
		{
			name:             "missing tenant id",
			secret:           dummySecret(secretName, namespace, stripKey(allKeys, "tenantId")),
			expectedAuthOpts: nil,
			expectedNotFound: false,
			expectedError:    ErrMissingAuthValue,
		},
		{
			name:             "missing domain name",
			secret:           dummySecret(secretName, namespace, stripKey(allKeys, "domainName")),
			expectedAuthOpts: nil,
			expectedNotFound: false,
			expectedError:    ErrMissingAuthValue,
		},
		{
			name:             "missing domain id",
			secret:           dummySecret(secretName, namespace, stripKey(allKeys, "domainId")),
			expectedAuthOpts: nil,
			expectedNotFound: false,
			expectedError:    ErrMissingAuthValue,
		},
		{
			name:             "missing username",
			secret:           dummySecret(secretName, namespace, stripKey(allKeys, "username")),
			expectedAuthOpts: nil,
			expectedNotFound: false,
			expectedError:    ErrMissingAuthValue,
		},
		{
			name:             "missing password",
			secret:           dummySecret(secretName, namespace, stripKey(allKeys, "password")),
			expectedAuthOpts: nil,
			expectedNotFound: false,
			expectedError:    ErrMissingAuthValue,
		},
		{
			name:             "missing identity endpoint",
			secret:           dummySecret(secretName, namespace, stripKey(allKeys, "identityEndpoint")),
			expectedAuthOpts: nil,
			expectedNotFound: false,
			expectedError:    ErrMissingAuthValue,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var client *fake.Clientset

			if tc.secret != nil {
				client = fake.NewClientset(tc.secret)
			} else {
				client = fake.NewClientset()
			}

			confProvider := authConfigProvider{
				client: client,
			}

			cfg, err := confProvider.Get(context.Background(), namespace, secretName)

			if tc.expectedNotFound {
				if err == nil {
					t.Error("expected not found error, got none")
					return
				}

				if !errors2.IsNotFound(err) {
					t.Errorf("expeted not found error, got: %v", err)
					return
				}

				return
			}

			if tc.expectedError != nil {
				if err == nil {
					t.Errorf("expected err: %v, got none", tc.expectedError)
					return
				}

				if !errors.Is(err, tc.expectedError) {
					t.Errorf("expected err: %v, got %v", tc.expectedError, err)
					return
				}

				return
			}

			if cfg.authOpts.TenantName != allKeys["tenantName"] {
				t.Errorf("got TenantName: %s, want %s", cfg.authOpts.TenantName, allKeys["tenantName"])
			}

			if cfg.authOpts.TenantID != allKeys["tenantId"] {
				t.Errorf("got TenantID: %s, want %s", cfg.authOpts.TenantID, allKeys["tenantId"])
			}

			if cfg.authOpts.DomainName != allKeys["domainName"] {
				t.Errorf("got DomainName: %s, want %s", cfg.authOpts.DomainName, allKeys["domainName"])
			}

			if cfg.authOpts.DomainID != allKeys["domainId"] {
				t.Errorf("got DomainID: %s, want %s", cfg.authOpts.DomainID, allKeys["domainId"])
			}

			if cfg.authOpts.Username != allKeys["username"] {
				t.Errorf("got Username: %s, want %s", cfg.authOpts.Username, allKeys["username"])
			}

			if cfg.authOpts.Password != allKeys["password"] {
				t.Errorf("got Password: %s, want %s", cfg.authOpts.Password, allKeys["password"])
			}

			if cfg.authOpts.IdentityEndpoint != allKeys["identityEndpoint"] {
				t.Errorf("got IdentityEndpoint: %s, want %s", cfg.authOpts.IdentityEndpoint, allKeys["identityEndpoint"])
			}

			if cfg.endpointOpts.Region != allKeys["region"] {
				t.Errorf("got Region: %s, want %s", cfg.endpointOpts.Region, allKeys["region"])
			}

			if !cfg.authOpts.AllowReauth {
				t.Errorf("got AllowReauth: %v, want true", cfg.authOpts.AllowReauth)
			}

		})
	}
}

func dummySecret(name, namespace string, data map[string]string) *corev1.Secret {
	result := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: map[string][]byte{},
	}

	for k, v := range data {
		result.Data[k] = []byte(v)
	}

	return result
}

func stripKey(allKeys map[string]string, keyToRemove string) map[string]string {
	result := make(map[string]string, len(allKeys))
	for k, v := range allKeys {
		result[k] = v
	}

	delete(result, keyToRemove)

	return result
}
