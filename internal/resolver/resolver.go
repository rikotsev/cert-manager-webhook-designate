package resolver

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

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
		zoneId, err = exactMatchZoneByName(ch.ResolvedZone, designateClient)
	case StrategyKindZoneName:
		zoneId, err = exactMatchZoneByName(*cfg.Strategy.ZoneName, designateClient)
	case StrategyKindBestEffort:
		zoneId, err = bestEffortMatchZone(ch.ResolvedFQDN, designateClient)
	}
	if err != nil {
		return err
	}

	allRecordSets, err := findRecordSetsForChallenge(ch, designateClient, zoneId)
	if err != nil {
		return err
	}

	record := enforceQuotes(ch.Key)

	if len(allRecordSets) == 0 {
		result := recordsets.Create(context.TODO(), designateClient, zoneId, recordsets.CreateOpts{
			Name:    enforceTrailingDot(ch.ResolvedFQDN),
			Type:    "TXT",
			Records: []string{record},
		})
		if result.Err != nil {
			return result.Err
		}

		return nil
	}

	if slices.Contains(allRecordSets[0].Records, record) {
		return nil
	}

	allRecordSets[0].Records = append(allRecordSets[0].Records, record)

	result := recordsets.Update(context.TODO(), designateClient, zoneId, allRecordSets[0].ID, recordsets.UpdateOpts{
		Records: allRecordSets[0].Records,
	})
	return result.Err
}

func (d *designateDnsResolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	designateClient, cfg, err := d.createDesignateClient(ch)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFailedDesignateClientInitialization, err)
	}

	var zoneId string

	switch cfg.Strategy.Kind {
	case StrategyKindSOA:
		zoneId, err = exactMatchZoneByName(ch.ResolvedZone, designateClient)
	case StrategyKindZoneName:
		zoneId, err = exactMatchZoneByName(*cfg.Strategy.ZoneName, designateClient)
	case StrategyKindBestEffort:
		zoneId, err = bestEffortMatchZone(ch.ResolvedFQDN, designateClient)
	}
	if err != nil {
		return err
	}

	allRecordSets, err := findRecordSetsForChallenge(ch, designateClient, zoneId)
	if err != nil {
		return err
	}

	if len(allRecordSets) == 0 {
		klog.V(4).Infof("No recordsets found for challenge %s", ch.ResolvedFQDN)
		return nil
	}

	record := enforceQuotes(ch.Key)

	if len(allRecordSets[0].Records) == 1 && allRecordSets[0].Records[0] == record {
		err = recordsets.Delete(context.TODO(), designateClient, zoneId, allRecordSets[0].ID).ExtractErr()
		if err != nil {
			return err
		}
		return nil
	}

	cleanedUpRecords := make([]string, 0)
	for _, rec := range allRecordSets[0].Records {
		if rec != record {
			cleanedUpRecords = append(cleanedUpRecords, rec)
		}
	}

	result := recordsets.Update(context.TODO(), designateClient, zoneId, allRecordSets[0].ID, recordsets.UpdateOpts{
		Records: cleanedUpRecords,
	})
	return result.Err
}

func (d *designateDnsResolver) Initialize(kubeClientConfig *rest.Config, _ <-chan struct{}) error {
	client, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	d.configProvider = &authConfigProvider{client: client}

	klog.V(2).Info(fmt.Sprintf("ACME DNS resolver - %s - initialized!", Name))

	return nil
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

func exactMatchZoneByName(zoneName string, designateClient *gophercloud.ServiceClient) (string, error) {
	zoneName = enforceTrailingDot(zoneName)
	page, err := zones.List(designateClient, zones.ListOpts{
		Name: zoneName,
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

func bestEffortMatchZone(fqdn string, designateClient *gophercloud.ServiceClient) (string, error) {
	fqdn = enforceTrailingDot(fqdn)
	page, err := zones.List(designateClient, zones.ListOpts{}).AllPages(context.TODO())
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

	var matchedZone *zones.Zone

	for i, z := range allZones {
		if strings.HasSuffix(fqdn, z.Name) {
			if matchedZone == nil {
				matchedZone = &allZones[i]
				continue
			}

			if len(z.Name) > len(matchedZone.Name) {
				matchedZone = &allZones[i]
			}
		}
	}

	if matchedZone == nil {
		return "", ErrNoZones
	}

	return matchedZone.ID, nil
}

func findRecordSetsForChallenge(ch *v1alpha1.ChallengeRequest, designateClient *gophercloud.ServiceClient, zoneId string) ([]recordsets.RecordSet, error) {
	allRecordsPages, err := recordsets.ListByZone(designateClient, zoneId, recordsets.ListOpts{
		Name: enforceTrailingDot(ch.ResolvedFQDN),
		Type: "TXT",
	}).AllPages(context.TODO())
	if err != nil {
		return nil, err
	}

	allRecordSets, err := recordsets.ExtractRecordSets(allRecordsPages)
	if err != nil {
		return nil, err
	}
	return allRecordSets, nil
}

func enforceTrailingDot(input string) string {
	if !strings.HasSuffix(input, ".") {
		input = input + "."
	}

	return input
}

func enforceQuotes(input string) string {
	if !strings.HasPrefix(input, "\"") && !strings.HasSuffix(input, "\"") {
		input = "\"" + input + "\""
	}

	return input
}

func New() webhook.Solver {
	return &designateDnsResolver{}
}
