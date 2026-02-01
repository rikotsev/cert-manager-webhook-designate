package resolver

import (
	"errors"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/utils/ptr"

	"testing"
)

func TestParseConfig(t *testing.T) {

	tcs := []struct {
		name           string
		input          string
		expectedConfig *ChallengeConfig
		expectedError  error
	}{
		{
			name: "parseable config with SOA strategy",
			input: `{
				"strategy":{
					"kind":"SOA"
				},
				"secretName":"foo",
				"secretNamespace":"bar"
			}`,
			expectedConfig: &ChallengeConfig{
				Strategy: &Strategy{
					Kind: StrategyKindSOA,
				},
				SecretName:      "foo",
				SecretNamespace: "bar",
			},
			expectedError: nil,
		},
		{
			name: "parseable config with BestEffort strategy",
			input: `{
				"strategy":{
					"kind":"BestEffort"
				},
				"secretName":"foo",
				"secretNamespace":"bar"
			}`,
			expectedConfig: &ChallengeConfig{
				Strategy: &Strategy{
					Kind: StrategyKindBestEffort,
				},
				SecretName:      "foo",
				SecretNamespace: "bar",
			},
			expectedError: nil,
		},
		{
			name: "parseable config with ZoneName strategy",
			input: `{
				"strategy":{
					"kind":"ZoneName",
					"zoneName":"example.com."
				},
				"secretName":"foo",
				"secretNamespace":"bar"
			}`,
			expectedConfig: &ChallengeConfig{
				Strategy: &Strategy{
					Kind:     StrategyKindZoneName,
					ZoneName: ptr.To("example.com."),
				},
				SecretName:      "foo",
				SecretNamespace: "bar",
			},
			expectedError: nil,
		},
		{
			name:           "unparseable config",
			input:          "{",
			expectedConfig: nil,
			expectedError:  ErrCannotParse,
		},
		{
			name: "missing strategy",
			input: `{
				"secretName": "foo",
				"secretNamespace": "bar"
			}`,
			expectedConfig: nil,
			expectedError:  ErrMissingRequiredField,
		},
		{
			name: "missing secretName",
			input: `{
				"strategy": {
					"kind": "SOA"
				},
				"secretNamespace": "bar"
			}`,
			expectedConfig: nil,
			expectedError:  ErrMissingRequiredField,
		},
		{
			name: "missing secretNamespace",
			input: `{
				"strategy": {
					"kind": "SOA"
				},
				"secretName": "foo"
			}`,
			expectedConfig: nil,
			expectedError:  ErrMissingRequiredField,
		},
		{
			name: "missing zoneName for ZoneName strategy",
			input: `{
				"strategy": {
					"kind": "ZoneName"
				},
				"secretName": "foo",
				"secretNamespace": "bar"
			}`,
			expectedConfig: nil,
			expectedError:  ErrMissingRequiredField,
		},
		{
			name: "invalid strategy",
			input: `{
				"strategy": {
					"kind": "Invalid"
				},
				"secretName": "foo",
				"secretNamespace": "bar"
			}`,
			expectedConfig: nil,
			expectedError:  ErrInvalidStrategy,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			config, err := ParseConfig(&apiextensionsv1.JSON{Raw: []byte(tc.input)})
			if tc.expectedError != nil {
				if err == nil {
					t.Error("expected error but got none")
					return
				}

				if !errors.Is(err, tc.expectedError) {
					t.Errorf("expected error %v but got %v", tc.expectedError, err)
					return
				}

				return
			}

			if tc.expectedConfig != nil && config == nil {
				t.Error("expected config but got none")
				return
			}

			if tc.expectedConfig.SecretName != config.SecretName {
				t.Errorf("expected secretName %v but got %v", tc.expectedConfig.SecretName, config.SecretName)
			}

			if tc.expectedConfig.SecretNamespace != config.SecretNamespace {
				t.Errorf("expected secretNamespace %v but got %v", tc.expectedConfig.SecretNamespace, config.SecretNamespace)
			}

			if tc.expectedConfig.Strategy.Kind != config.Strategy.Kind {
				t.Errorf("expected strategy kind %v but got %v", tc.expectedConfig.Strategy.Kind, config.Strategy.Kind)
			}

			if tc.expectedConfig.Strategy.Kind == StrategyKindZoneName &&
				*tc.expectedConfig.Strategy.ZoneName != *config.Strategy.ZoneName {
				t.Errorf("expected zoneName %v but got %v", tc.expectedConfig.Strategy.ZoneName, config.Strategy.ZoneName)
			}
		})
	}

}
