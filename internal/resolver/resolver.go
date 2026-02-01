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
	designateClient, err := d.createDesignateClient(ch)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFailedDesignateClientInitialization, err)
	}

	page, err := zones.List(designateClient, zones.ListOpts{
		Name: ch.ResolvedFQDN,
	}).AllPages(context.TODO())
	if err != nil {
		return err
	}

	allZones, err := zones.ExtractZones(page)
	if err != nil {
		return err
	}
	if len(allZones) == 0 {
		return ErrNoZones
	}

	result := recordsets.Create(context.TODO(), designateClient, allZones[0].ID, recordsets.CreateOpts{
		Name:    ch.ResolvedFQDN,
		Type:    "TXT",
		Records: []string{ch.Key},
	})
	if result.Err != nil {
		return result.Err
	}

	return nil
}

func (d *designateDnsResolver) createDesignateClient(ch *v1alpha1.ChallengeRequest) (*gophercloud.ServiceClient, error) {
	ctx := context.TODO()

	cfg, err := ParseConfig(ch.Config)
	if err != nil {
		return nil, err
	}

	authCfg, err := d.configProvider.Get(ctx, cfg.SecretNamespace, cfg.SecretName)
	if err != nil {
		return nil, err
	}

	client, err := openstack.AuthenticatedClient(ctx, authCfg.authOpts)
	if err != nil {
		return nil, err
	}

	designateClient, err := openstack.NewDNSV2(client, authCfg.endpointOpts)
	if err != nil {
		return nil, err
	}
	return designateClient, nil
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
