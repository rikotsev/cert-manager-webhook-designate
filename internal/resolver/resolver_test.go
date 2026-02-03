package resolver

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/gophercloud/gophercloud/v2/openstack/dns/v2/recordsets"
	mockresolver "github.com/rikotsev/cert-manager-webhook-designate/internal/resolver/mock"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestDesignateDnsResolver_Present(t *testing.T) {
	tcs := []struct {
		name                    string
		zones                   []mockresolver.MockZone
		recordSets              []mockresolver.MockRecordSet
		secret                  *corev1.Secret
		challengeRequest        *v1alpha1.ChallengeRequest
		expectedError           error
		expectedZoneUpdate      *mockresolver.ZoneUpdate
		expectedRecordSetPut    *mockresolver.RecordSetPut
		mockErrorListingZones   bool
		mockErrorAuthenticating bool
		generalError            bool
	}{
		{
			name: "present challenge with SOA strategy - happy path",
			zones: []mockresolver.MockZone{
				{
					ID:   "12345",
					Name: "example.com.",
				},
				{
					ID:   "67890",
					Name: "test.example.com.",
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "bar",
				},
				Data: map[string][]byte{
					"tenantName": []byte("testTenant"),
					"tenantId":   []byte("testTenantId"),
					"domainName": []byte("testDomainName"),
					"domainId":   []byte("testDomainId"),
					"username":   []byte("john-doe"),
					"password":   []byte("secretpass"),
					"region":     []byte("RegionOne"),
				},
			},
			challengeRequest: &v1alpha1.ChallengeRequest{
				UID:                     "",
				Action:                  "",
				Type:                    "",
				DNSName:                 "",
				Key:                     "challenge",
				ResourceNamespace:       "",
				ResolvedFQDN:            "cool.example.com",
				ResolvedZone:            "",
				AllowAmbientCredentials: false,
				Config: &apiextensionsv1.JSON{Raw: []byte(`{
					"secretName": "foo",
					"secretNamespace": "bar",
					"strategy": {
						"kind": "SOA"
					}
				}`)},
			},
			expectedError: nil,
			expectedZoneUpdate: &mockresolver.ZoneUpdate{
				ZoneID: "12345",
				Opts: recordsets.CreateOpts{
					Name:    "cool.example.com",
					Type:    "TXT",
					Records: []string{"challenge"},
				},
			},
		},
		{
			name: "present challenge with ZoneName strategy - happy path",
			zones: []mockresolver.MockZone{
				{
					ID:   "12345",
					Name: "example.com.",
				},
				{
					ID:   "67890",
					Name: "test.example.com.",
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "bar",
				},
				Data: map[string][]byte{
					"tenantName": []byte("testTenant"),
					"tenantId":   []byte("testTenantId"),
					"domainName": []byte("testDomainName"),
					"domainId":   []byte("testDomainId"),
					"username":   []byte("john-doe"),
					"password":   []byte("secretpass"),
					"region":     []byte("RegionOne"),
				},
			},
			challengeRequest: &v1alpha1.ChallengeRequest{
				UID:                     "",
				Action:                  "",
				Type:                    "",
				DNSName:                 "",
				Key:                     "challenge",
				ResourceNamespace:       "",
				ResolvedFQDN:            "cool.example.com",
				ResolvedZone:            "",
				AllowAmbientCredentials: false,
				Config: &apiextensionsv1.JSON{Raw: []byte(`{
					"secretName": "foo",
					"secretNamespace": "bar",
					"strategy": {
						"kind": "ZoneName",
						"zoneName": "example.com."
					}
				}`)},
			},
			expectedError: nil,
			expectedZoneUpdate: &mockresolver.ZoneUpdate{
				ZoneID: "12345",
				Opts: recordsets.CreateOpts{
					Name:    "cool.example.com",
					Type:    "TXT",
					Records: []string{"challenge"},
				},
			},
		},
		{
			name: "present challenge with BestEffort strategy - happy path",
			zones: []mockresolver.MockZone{
				{
					ID:   "12345",
					Name: "example.com.",
				},
				{
					ID:   "67890",
					Name: "test.example.com.",
				},
				{
					ID:   "12312",
					Name: "api.test.example.com",
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "bar",
				},
				Data: map[string][]byte{
					"tenantName": []byte("testTenant"),
					"tenantId":   []byte("testTenantId"),
					"domainName": []byte("testDomainName"),
					"domainId":   []byte("testDomainId"),
					"username":   []byte("john-doe"),
					"password":   []byte("secretpass"),
					"region":     []byte("RegionOne"),
				},
			},
			challengeRequest: &v1alpha1.ChallengeRequest{
				UID:                     "",
				Action:                  "",
				Type:                    "",
				DNSName:                 "",
				Key:                     "challenge",
				ResourceNamespace:       "",
				ResolvedFQDN:            "my.api.test.example.com",
				ResolvedZone:            "example.com",
				AllowAmbientCredentials: false,
				Config: &apiextensionsv1.JSON{Raw: []byte(`{
					"secretName": "foo",
					"secretNamespace": "bar",
					"strategy": {
						"kind": "BestEffort"
					}
				}`)},
			},
			expectedError: nil,
			expectedZoneUpdate: &mockresolver.ZoneUpdate{
				ZoneID: "12312",
				Opts: recordsets.CreateOpts{
					Name:    "my.api.test.example.com",
					Type:    "TXT",
					Records: []string{"challenge"},
				},
			},
		},
		{
			name: "present challenge with SOA strategy - update existing recordset",
			zones: []mockresolver.MockZone{
				{
					ID:   "12345",
					Name: "example.com.",
				},
				{
					ID:   "67890",
					Name: "test.example.com.",
				},
			},
			recordSets: []mockresolver.MockRecordSet{
				{
					ID:     "12345-1",
					ZoneID: "12345",
					Name:   "cool.example.com",
					Type:   "TXT",
					Records: []string{
						"another-record",
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "bar",
				},
				Data: map[string][]byte{
					"tenantName": []byte("testTenant"),
					"tenantId":   []byte("testTenantId"),
					"domainName": []byte("testDomainName"),
					"domainId":   []byte("testDomainId"),
					"username":   []byte("john-doe"),
					"password":   []byte("secretpass"),
					"region":     []byte("RegionOne"),
				},
			},
			challengeRequest: &v1alpha1.ChallengeRequest{
				UID:                     "",
				Action:                  "",
				Type:                    "",
				DNSName:                 "",
				Key:                     "challenge",
				ResourceNamespace:       "",
				ResolvedFQDN:            "cool.example.com",
				ResolvedZone:            "example.com.",
				AllowAmbientCredentials: false,
				Config: &apiextensionsv1.JSON{Raw: []byte(`{
					"secretName": "foo",
					"secretNamespace": "bar",
					"strategy": {
						"kind": "SOA"
					}
				}`)},
			},
			expectedError: nil,
			expectedRecordSetPut: &mockresolver.RecordSetPut{
				ZoneID:      "12345",
				RecordSetID: "12345-1",
				Opts: recordsets.UpdateOpts{
					Records: []string{"another-record", "challenge"},
				},
			},
		},
		{
			name: "present challenge - failed initialization",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "bar",
				},
			},
			challengeRequest: &v1alpha1.ChallengeRequest{
				UID:                     "",
				Action:                  "",
				Type:                    "",
				DNSName:                 "",
				Key:                     "challenge",
				ResourceNamespace:       "",
				ResolvedFQDN:            "test.example.com",
				ResolvedZone:            "",
				AllowAmbientCredentials: false,
				Config: &apiextensionsv1.JSON{Raw: []byte(`{
					"secretName": "not-existing",
					"secretNamespace": "bar",
					"strategy": {
						"kind": "SOA"
					}
				}`)},
			},
			expectedError:      ErrFailedDesignateClientInitialization,
			expectedZoneUpdate: nil,
		},
		{
			name:  "no zones available",
			zones: []mockresolver.MockZone{},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "bar",
				},
				Data: map[string][]byte{
					"tenantName": []byte("testTenant"),
					"tenantId":   []byte("testTenantId"),
					"domainName": []byte("testDomainName"),
					"domainId":   []byte("testDomainId"),
					"username":   []byte("john-doe"),
					"password":   []byte("secretpass"),
					"region":     []byte("RegionOne"),
				},
			},
			challengeRequest: &v1alpha1.ChallengeRequest{
				UID:                     "",
				Action:                  "",
				Type:                    "",
				DNSName:                 "",
				Key:                     "challenge",
				ResourceNamespace:       "",
				ResolvedFQDN:            "test.example.com",
				ResolvedZone:            "",
				AllowAmbientCredentials: false,
				Config: &apiextensionsv1.JSON{Raw: []byte(`{
					"secretName": "foo",
					"secretNamespace": "bar",
					"strategy": {
						"kind": "SOA"
					}
				}`)},
			},
			expectedError:      ErrNoZones,
			expectedZoneUpdate: nil,
		},
		{
			name: "no zone matched the name - strategy ZoneName",
			zones: []mockresolver.MockZone{
				{
					ID:   "67890",
					Name: "example.com.",
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "bar",
				},
				Data: map[string][]byte{
					"tenantName": []byte("testTenant"),
					"tenantId":   []byte("testTenantId"),
					"domainName": []byte("testDomainName"),
					"domainId":   []byte("testDomainId"),
					"username":   []byte("john-doe"),
					"password":   []byte("secretpass"),
					"region":     []byte("RegionOne"),
				},
			},
			challengeRequest: &v1alpha1.ChallengeRequest{
				UID:                     "",
				Action:                  "",
				Type:                    "",
				DNSName:                 "",
				Key:                     "challenge",
				ResourceNamespace:       "",
				ResolvedFQDN:            "test.example.com",
				ResolvedZone:            "",
				AllowAmbientCredentials: false,
				Config: &apiextensionsv1.JSON{Raw: []byte(`{
					"secretName": "foo",
					"secretNamespace": "bar",
					"strategy": {
						"kind": "ZoneName",
						"zoneName": "test.example.com."
					}
				}`)},
			},
			expectedError:      ErrNoZones,
			expectedZoneUpdate: nil,
		},
		{
			name: "no zone matched the name - strategy BestEffort",
			zones: []mockresolver.MockZone{
				{
					ID:   "12345",
					Name: "bar.com.",
				},
				{
					ID:   "67890",
					Name: "foo.com.",
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "bar",
				},
				Data: map[string][]byte{
					"tenantName": []byte("testTenant"),
					"tenantId":   []byte("testTenantId"),
					"domainName": []byte("testDomainName"),
					"domainId":   []byte("testDomainId"),
					"username":   []byte("john-doe"),
					"password":   []byte("secretpass"),
					"region":     []byte("RegionOne"),
				},
			},
			challengeRequest: &v1alpha1.ChallengeRequest{
				UID:                     "",
				Action:                  "",
				Type:                    "",
				DNSName:                 "",
				Key:                     "challenge",
				ResourceNamespace:       "",
				ResolvedFQDN:            "test.example.com",
				ResolvedZone:            "example.com",
				AllowAmbientCredentials: false,
				Config: &apiextensionsv1.JSON{Raw: []byte(`{
					"secretName": "foo",
					"secretNamespace": "bar",
					"strategy": {
						"kind": "BestEffort"
					}
				}`)},
			},
			expectedError:      ErrNoZones,
			expectedZoneUpdate: nil,
		},
		{
			name: "present challenge - authentication error",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "bar",
				},
				Data: map[string][]byte{
					"tenantName": []byte("testTenant"),
					"tenantId":   []byte("testTenantId"),
					"domainName": []byte("testDomainName"),
					"domainId":   []byte("testDomainId"),
					"username":   []byte("john-doe"),
					"password":   []byte("secretpass"),
					"region":     []byte("RegionOne"),
				},
			},
			challengeRequest: &v1alpha1.ChallengeRequest{
				UID:                     "",
				Action:                  "",
				Type:                    "",
				DNSName:                 "",
				Key:                     "challenge",
				ResourceNamespace:       "",
				ResolvedFQDN:            "test.example.com",
				ResolvedZone:            "",
				AllowAmbientCredentials: false,
				Config: &apiextensionsv1.JSON{Raw: []byte(`{
					"secretName": "foo",
					"secretNamespace": "bar",
					"strategy": {
						"kind": "SOA"
					}
				}`)},
			},
			mockErrorAuthenticating: true,
			expectedError:           ErrFailedDesignateClientInitialization,
			expectedZoneUpdate:      nil,
		},
		{
			name:  "present challenge - error listing zones",
			zones: []mockresolver.MockZone{},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "bar",
				},
				Data: map[string][]byte{
					"tenantName": []byte("testTenant"),
					"tenantId":   []byte("testTenantId"),
					"domainName": []byte("testDomainName"),
					"domainId":   []byte("testDomainId"),
					"username":   []byte("john-doe"),
					"password":   []byte("secretpass"),
					"region":     []byte("RegionOne"),
				},
			},
			challengeRequest: &v1alpha1.ChallengeRequest{
				UID:                     "",
				Action:                  "",
				Type:                    "",
				DNSName:                 "",
				Key:                     "challenge",
				ResourceNamespace:       "",
				ResolvedFQDN:            "test.example.com",
				ResolvedZone:            "",
				AllowAmbientCredentials: false,
				Config: &apiextensionsv1.JSON{Raw: []byte(`{
					"secretName": "foo",
					"secretNamespace": "bar",
					"strategy": {
						"kind": "SOA"
					}
				}`)},
			},
			mockErrorListingZones: true,
			generalError:          true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			mockApi := mockresolver.CreateMockOpenstackApi(t)
			mockApi.Zones = tc.zones
			mockApi.RecordSets = tc.recordSets
			mockApi.ErrorListingZones = tc.mockErrorListingZones
			mockApi.ErrorAuthenticating = tc.mockErrorAuthenticating
			openstackMock := httptest.NewServer(mockApi)
			defer openstackMock.Close()

			if tc.secret != nil {
				secretCopy := tc.secret.DeepCopy()
				if secretCopy.Data == nil {
					secretCopy.Data = make(map[string][]byte)
				}
				secretCopy.Data["identityEndpoint"] = []byte(openstackMock.URL)
				tc.secret = secretCopy
			}

			resolver := new(designateDnsResolver)
			resolver.configProvider = &authConfigProvider{
				client: fake.NewClientset(tc.secret),
			}

			err := resolver.Present(tc.challengeRequest)

			if tc.generalError {
				if err == nil {
					t.Errorf("expected an error, got none")
					return
				}
			} else {
				if !errors.Is(err, tc.expectedError) {
					t.Errorf("expected error %v, got %v", tc.expectedError, err)
					return
				}
			}

			if tc.expectedZoneUpdate != nil {
				if len(mockApi.Updates) != 1 {
					t.Errorf("expected 1 update, got %d", len(mockApi.Updates))
					return
				}

				update := mockApi.Updates[0]
				if update.ZoneID != tc.expectedZoneUpdate.ZoneID {
					t.Errorf("expected zone ID %s, got %s", tc.expectedZoneUpdate.ZoneID, update.ZoneID)
				}
				if update.Opts.Name != tc.expectedZoneUpdate.Opts.Name {
					t.Errorf("expected name %s, got %s", tc.expectedZoneUpdate.Opts.Name, update.Opts.Name)
				}
				if update.Opts.Type != tc.expectedZoneUpdate.Opts.Type {
					t.Errorf("expected type %s, got %s", tc.expectedZoneUpdate.Opts.Type, update.Opts.Type)
				}
				if len(update.Opts.Records) != len(tc.expectedZoneUpdate.Opts.Records) {
					t.Errorf("expected records length %d, got %d", len(tc.expectedZoneUpdate.Opts.Records), len(update.Opts.Records))
				} else {
					for i, r := range update.Opts.Records {
						if r != tc.expectedZoneUpdate.Opts.Records[i] {
							t.Errorf("expected record %s at index %d, got %s", tc.expectedZoneUpdate.Opts.Records[i], i, r)
						}
					}
				}
				return
			}

			if tc.expectedRecordSetPut != nil {
				if len(mockApi.RecordSetPuts) != 1 {
					t.Errorf("expected 1 put, got %d", len(mockApi.RecordSetPuts))
					return
				}

				put := mockApi.RecordSetPuts[0]

				if put.ZoneID != tc.expectedRecordSetPut.ZoneID {
					t.Errorf("expected zone ID %s, got %s", tc.expectedRecordSetPut.ZoneID, put.ZoneID)
				}

				if put.RecordSetID != tc.expectedRecordSetPut.RecordSetID {
					t.Errorf("expected record set ID %s, got %s", tc.expectedRecordSetPut.RecordSetID, put.RecordSetID)
				}

				for i, r := range put.Opts.Records {
					if r != tc.expectedRecordSetPut.Opts.Records[i] {
						t.Errorf("expected record %s at index %d, got %s", tc.expectedRecordSetPut.Opts.Records[i], i, r)
					}
				}
			}
		})
	}
}

func TestDesignateDnsResolver_CleanUp(t *testing.T) {
	tcs := []struct {
		name                    string
		zones                   []mockresolver.MockZone
		recordSets              []mockresolver.MockRecordSet
		secret                  *corev1.Secret
		challengeRequest        *v1alpha1.ChallengeRequest
		expectedError           error
		expectedRecordSetDelete *mockresolver.RecordSetDelete
		expectedRecordSetPut    *mockresolver.RecordSetPut
	}{
		{
			name: "cleanup challenge with SOA strategy - delete recordset",
			zones: []mockresolver.MockZone{
				{
					ID:   "12345",
					Name: "example.com.",
				},
				{
					ID:   "67890",
					Name: "test.example.com.",
				},
			},
			recordSets: []mockresolver.MockRecordSet{
				{
					ID:     "12345-1",
					ZoneID: "12345",
					Name:   "cool.example.com",
					Type:   "TXT",
					Records: []string{
						"challenge",
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "bar",
				},
				Data: map[string][]byte{
					"tenantName": []byte("testTenant"),
					"tenantId":   []byte("testTenantId"),
					"domainName": []byte("testDomainName"),
					"domainId":   []byte("testDomainId"),
					"username":   []byte("john-doe"),
					"password":   []byte("secretpass"),
					"region":     []byte("RegionOne"),
				},
			},
			challengeRequest: &v1alpha1.ChallengeRequest{
				UID:                     "",
				Action:                  "",
				Type:                    "",
				DNSName:                 "",
				Key:                     "challenge",
				ResourceNamespace:       "",
				ResolvedFQDN:            "cool.example.com",
				ResolvedZone:            "",
				AllowAmbientCredentials: false,
				Config: &apiextensionsv1.JSON{Raw: []byte(`{
					"secretName": "foo",
					"secretNamespace": "bar",
					"strategy": {
						"kind": "SOA"
					}
				}`)},
			},
			expectedRecordSetDelete: &mockresolver.RecordSetDelete{
				ZoneID:      "12345",
				RecordSetID: "12345-1",
			},
		},
		{
			name: "cleanup challenge with SOA strategy - remove only challenge record",
			zones: []mockresolver.MockZone{
				{
					ID:   "12345",
					Name: "example.com.",
				},
				{
					ID:   "67890",
					Name: "test.example.com.",
				},
			},
			recordSets: []mockresolver.MockRecordSet{
				{
					ID:     "12345-1",
					ZoneID: "12345",
					Name:   "cool.example.com",
					Type:   "TXT",
					Records: []string{
						"challenge",
						"another-record",
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "bar",
				},
				Data: map[string][]byte{
					"tenantName": []byte("testTenant"),
					"tenantId":   []byte("testTenantId"),
					"domainName": []byte("testDomainName"),
					"domainId":   []byte("testDomainId"),
					"username":   []byte("john-doe"),
					"password":   []byte("secretpass"),
					"region":     []byte("RegionOne"),
				},
			},
			challengeRequest: &v1alpha1.ChallengeRequest{
				UID:                     "",
				Action:                  "",
				Type:                    "",
				DNSName:                 "",
				Key:                     "challenge",
				ResourceNamespace:       "",
				ResolvedFQDN:            "cool.example.com",
				ResolvedZone:            "",
				AllowAmbientCredentials: false,
				Config: &apiextensionsv1.JSON{Raw: []byte(`{
					"secretName": "foo",
					"secretNamespace": "bar",
					"strategy": {
						"kind": "SOA"
					}
				}`)},
			},
			expectedRecordSetPut: &mockresolver.RecordSetPut{
				ZoneID:      "12345",
				RecordSetID: "12345-1",
				Opts: recordsets.UpdateOpts{
					Records: []string{
						"another-record",
					},
				},
			},
		},
		{
			name: "cleanup challenge with SOA strategy - no recordset to found",
			zones: []mockresolver.MockZone{
				{
					ID:   "12345",
					Name: "example.com.",
				},
				{
					ID:   "67890",
					Name: "test.example.com.",
				},
			},
			recordSets: []mockresolver.MockRecordSet{},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "bar",
				},
				Data: map[string][]byte{
					"tenantName": []byte("testTenant"),
					"tenantId":   []byte("testTenantId"),
					"domainName": []byte("testDomainName"),
					"domainId":   []byte("testDomainId"),
					"username":   []byte("john-doe"),
					"password":   []byte("secretpass"),
					"region":     []byte("RegionOne"),
				},
			},
			challengeRequest: &v1alpha1.ChallengeRequest{
				UID:                     "",
				Action:                  "",
				Type:                    "",
				DNSName:                 "",
				Key:                     "challenge",
				ResourceNamespace:       "",
				ResolvedFQDN:            "cool.example.com",
				ResolvedZone:            "",
				AllowAmbientCredentials: false,
				Config: &apiextensionsv1.JSON{Raw: []byte(`{
					"secretName": "foo",
					"secretNamespace": "bar",
					"strategy": {
						"kind": "SOA"
					}
				}`)},
			},
			expectedError: nil,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			mockApi := mockresolver.CreateMockOpenstackApi(t)
			mockApi.Zones = tc.zones
			mockApi.RecordSets = tc.recordSets

			openstackMock := httptest.NewServer(mockApi)
			defer openstackMock.Close()

			if tc.secret != nil {
				secretCopy := tc.secret.DeepCopy()
				if secretCopy.Data == nil {
					secretCopy.Data = make(map[string][]byte)
				}
				secretCopy.Data["identityEndpoint"] = []byte(openstackMock.URL)
				tc.secret = secretCopy
			}

			resolver := new(designateDnsResolver)
			resolver.configProvider = &authConfigProvider{
				client: fake.NewClientset(tc.secret),
			}

			err := resolver.CleanUp(tc.challengeRequest)

			if tc.expectedError != nil {
				if err == nil {
					t.Errorf("expected an error, got none")
					return
				} else if !errors.Is(err, tc.expectedError) {
					t.Errorf("expected error %v, got %v", tc.expectedError, err)
					return
				}

				return
			}

			if tc.expectedRecordSetDelete != nil {
				if len(mockApi.RecordSetDeletes) != 1 {
					t.Errorf("expected 1 delete, got %d", len(mockApi.RecordSetDeletes))
					return
				}

				deleteAction := mockApi.RecordSetDeletes[0]
				if deleteAction.ZoneID != tc.expectedRecordSetDelete.ZoneID {
					t.Errorf("expected delete zone ID %s, got %s", tc.expectedRecordSetDelete.ZoneID, deleteAction.ZoneID)
				}
				if deleteAction.RecordSetID != tc.expectedRecordSetDelete.RecordSetID {
					t.Errorf("expected delete record set ID %s, got %s", tc.expectedRecordSetDelete.RecordSetID, deleteAction.RecordSetID)
				}

				return
			}

			if tc.expectedRecordSetPut != nil {
				if len(mockApi.RecordSetPuts) != 1 {
					t.Errorf("expected 1 put, got %d", len(mockApi.RecordSetPuts))
					return
				}

				putAction := mockApi.RecordSetPuts[0]
				if putAction.ZoneID != tc.expectedRecordSetPut.ZoneID {
					t.Errorf("expected put zone ID %s, got %s", tc.expectedRecordSetPut.ZoneID, putAction.ZoneID)
				}

				if putAction.RecordSetID != tc.expectedRecordSetPut.RecordSetID {
					t.Errorf("expected put record set ID %s, got %s", tc.expectedRecordSetPut.RecordSetID, putAction.RecordSetID)
				}

				if len(putAction.Opts.Records) != len(tc.expectedRecordSetPut.Opts.Records) {
					t.Errorf("expected records length %d, got %d", len(tc.expectedRecordSetPut.Opts.Records), len(putAction.Opts.Records))
				}

				for i, r := range putAction.Opts.Records {
					if r != tc.expectedRecordSetPut.Opts.Records[i] {
						t.Errorf("expected record %s at index %d, got %s", tc.expectedRecordSetPut.Opts.Records[i], i, r)
					}
				}
			}
		})
	}
}
