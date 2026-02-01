package resolver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

const (
	// StrategyKindSOA
	// This determines the SOA (Start of Authority) based on the FQDN and DNS records
	// something that cert-manager already does.
	StrategyKindSOA = "SOA"

	// StrategyKindBestEffort
	// This checks all possible dns zones in openstack and tries to find the closest match
	// then creates the DNS challenge in that zone.
	StrategyKindBestEffort = "BestEffort"

	// StrategyKindZoneName
	// Forces always to use a particular zone name, regardless of everything else.
	StrategyKindZoneName = "ZoneName"
)

var ErrCannotParse = errors.New("cannot parse the config")
var ErrMissingRequiredField = errors.New("missing required field")
var ErrInvalidStrategy = errors.New("unrecognized strategy")

type Strategy struct {
	Kind     string  `json:"kind"`
	ZoneName *string `json:"zoneName,omitempty"`
}

type ChallengeConfig struct {
	SecretName      string    `json:"secretName"`
	SecretNamespace string    `json:"secretNamespace"`
	Strategy        *Strategy `json:"strategy,omitempty"`
}

func ParseConfig(input *apiextensionsv1.JSON) (*ChallengeConfig, error) {
	result := new(ChallengeConfig)

	err := json.NewDecoder(bytes.NewReader(input.Raw)).Decode(result)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCannotParse, err)
	}

	if result.SecretName == "" {
		return nil, fmt.Errorf("%w: %s", ErrMissingRequiredField, "secretName")
	}

	if result.SecretNamespace == "" {
		return nil, fmt.Errorf("%w: %s", ErrMissingRequiredField, "secretNamespace")
	}

	if result.Strategy == nil {
		return nil, fmt.Errorf("%w: %s", ErrMissingRequiredField, "strategy")
	}

	if result.Strategy.Kind != StrategyKindSOA &&
		result.Strategy.Kind != StrategyKindBestEffort &&
		result.Strategy.Kind != StrategyKindZoneName {
		return nil, fmt.Errorf("%w: %s", ErrInvalidStrategy, "strategy")
	}

	if result.Strategy.Kind == StrategyKindZoneName && result.Strategy.ZoneName == nil {
		return nil, fmt.Errorf("%w: %s", ErrMissingRequiredField, "strategy.zoneName")
	}

	return result, nil
}
