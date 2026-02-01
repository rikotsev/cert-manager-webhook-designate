package resolver

import (
	"context"
	"errors"
	"fmt"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/dns/v2/recordsets"
	"github.com/gophercloud/gophercloud/v2/openstack/dns/v2/zones"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"k8s.io/client-go/rest"
)

const Name = "openstack-designate"

var ErrFailedDesignateClientInitialization = errors.New("failed to initialize the designate client")
var ErrNoZones = errors.New("there are no zones in designate to match from for the challenge")

type designateDnsResolver struct {
	configProvider *authConfigProvider
}

var _ webhook.Solver = (*designateDnsResolver)(nil)

func (d *designateDnsResolver) Name() string {
	return Name
}

func (d *designateDnsResolver) Present(ch *v1alpha1.ChallengeRequest) error {
	designateClient, cfg, err := d.createDesignateClient(ch)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFailedDesignateClientInitialization, err)
	}

	var zoneId string

	switch cfg.Strategy.Kind {
	case StrategyKindSOA:
		zoneId, err = d.soa(ch, err, designateClient)
		if err != nil {
			return err
		}
	}

	result := recordsets.Create(context.TODO(), designateClient, zoneId, recordsets.CreateOpts{
		Name:    ch.ResolvedFQDN,
		Type:    "TXT",
		Records: []string{ch.Key},
	})
	if result.Err != nil {
		return result.Err
	}

	return nil
}

func (d *designateDnsResolver) soa(ch *v1alpha1.ChallengeRequest, err error, designateClient *gophercloud.ServiceClient) (string, error) {
	page, err := zones.List(designateClient, zones.ListOpts{
		Name: ch.ResolvedFQDN,
	}).AllPages(context.TODO())
	if err != nil {
		return "", err
	}

	allZones, err := zones.ExtractZones(page)
	if err != nil {
		return "", err
	}
	if len(allZones) == 0 {
		return "", ErrNoZones
	}

	zoneId := allZones[0].ID
	return zoneId, nil
}

func (d *designateDnsResolver) createDesignateClient(ch *v1alpha1.ChallengeRequest) (*gophercloud.ServiceClient, *ChallengeConfig, error) {
	ctx := context.TODO()

	cfg, err := ParseConfig(ch.Config)
	if err != nil {
		return nil, nil, err
	}

	authCfg, err := d.configProvider.Get(ctx, cfg.SecretNamespace, cfg.SecretName)
	if err != nil {
		return nil, cfg, err
	}

	client, err := openstack.AuthenticatedClient(ctx, authCfg.authOpts)
	if err != nil {
		return nil, cfg, err
	}

	designateClient, err := openstack.NewDNSV2(client, authCfg.endpointOpts)
	if err != nil {
		return nil, cfg, err
	}
	return designateClient, cfg, nil
}

func (d *designateDnsResolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	//TODO implement me
	panic("implement me")
}

func (d *designateDnsResolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	client, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	d.configProvider = &authConfigProvider{client: client}

	klog.V(2).Info(fmt.Sprintf("ACME DNS resolver - %s - initialized!", Name))

	return nil
}

func New() webhook.Solver {
	return &designateDnsResolver{}
}
