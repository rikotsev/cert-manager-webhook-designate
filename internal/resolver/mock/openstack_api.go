package mockresolver

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/gophercloud/gophercloud/v2/openstack/dns/v2/recordsets"
)

type MockZone struct {
	ID   string
	Name string
}

type MockRecordSet struct {
	ID      string
	ZoneID  string
	Name    string
	Type    string
	Records []string
}

type ZoneUpdate struct {
	ZoneID string
	Opts   recordsets.CreateOpts
}

type RecordSetDelete struct {
	ZoneID      string
	RecordSetID string
}

type RecordSetPut struct {
	ZoneID      string
	RecordSetID string
	Opts        recordsets.UpdateOpts
}

type OpenstackApiMock struct {
	t                   *testing.T
	Zones               []MockZone
	RecordSets          []MockRecordSet
	Updates             []ZoneUpdate
	RecordSetDeletes    []RecordSetDelete
	RecordSetPuts       []RecordSetPut
	ErrorListingZones   bool
	ErrorAuthenticating bool
}

func (o *OpenstackApiMock) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	content, err := io.ReadAll(r.Body)
	if err != nil {
		o.t.Errorf("failed to receive versions request")
	}

	slog.Info("mock openstack API request", "method", r.Method, "url", r.URL, "content", content)

	// list all versions
	if (r.Method == http.MethodGet && r.URL.Path == "/") ||
		r.Method == http.MethodGet && r.URL.Path == "/dns/" {
		slog.Info("matched versions mock response")
		w.WriteHeader(http.StatusOK)
		jsonResponse := `{
				"versions": {
					"values": [
						{
							"id": "v2.0",
							"status": "supported",
							"links": [
								{
									"href": "<URL>",
									"rel": "self"
								}
							]
						}
					]
				}
			}`
		_, err = w.Write([]byte(strings.Replace(jsonResponse, "<URL>", "http://"+r.Host, 1)))
		if err != nil {
			o.t.Error("failed to write versions response")
		}
		return
	}

	// authenticate for version
	if r.Method == http.MethodPost && r.URL.Path == "/tokens" {
		if o.ErrorAuthenticating {
			slog.Info("simulating authentication error")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		slog.Info("matched /tokens mock response")
		w.WriteHeader(http.StatusOK)
		jsonResponse := `{
				"access": {
					"token": {
						"id": "mock-token"
					},
					"serviceCatalog": [
						{
							"name": "dns",
							"type": "dns",
							"endpoints": [
								{
									"tenantId": "testTenantId",
									"publicURL": "<URL>",
									"region": "RegionOne",
									"versionId": "2.0"
								}
							]
						}
					]
				}
			}`
		_, err = w.Write([]byte(strings.Replace(jsonResponse, "<URL>", "http://"+r.Host+"/dns", 1)))
		if err != nil {
			o.t.Error("failed to write versions response")
		}
		return
	}

	// list zones
	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/dns/v2/zones") && !strings.Contains(r.URL.Path, "/recordsets") {
		if o.ErrorListingZones {
			slog.Info("simulating list zones error")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		slog.Info("matched /dns/v2/zones mock response")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		zoneName := r.URL.Query().Get("name")

		var matchingZones []MockZone
		if zoneName != "" {
			for _, z := range o.Zones {
				if z.Name == zoneName || z.Name == zoneName+"." {
					matchingZones = append(matchingZones, z)
				}
			}
		} else {
			matchingZones = o.Zones
		}

		var enrichedZones []map[string]interface{}
		for _, z := range matchingZones {
			enrichedZones = append(enrichedZones, map[string]interface{}{
				"id":          z.ID,
				"name":        z.Name,
				"email":       "admin@example.com",
				"ttl":         3600,
				"serial":      1,
				"status":      "ACTIVE",
				"action":      "NONE",
				"description": "Mock Zone",
				"type":        "PRIMARY",
			})
		}

		resp := map[string]interface{}{
			"zones":    enrichedZones,
			"links":    map[string]string{"self": fmt.Sprintf("http://%s/dns/v2/zones", r.Host)},
			"metadata": map[string]interface{}{"total_count": len(matchingZones)},
		}

		if err := json.NewEncoder(w).Encode(resp); err != nil {
			o.t.Error("failed to write zones response")
		}
		return
	}

	// create recordset
	if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/dns/v2/zones") && strings.Contains(r.URL.Path, "/recordsets") {
		slog.Info("matched create recordset mock response")

		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 5 {
			o.t.Errorf("invalid recordset creation URL, too short: %s", r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		zoneID := parts[4]

		var opts recordsets.CreateOpts
		if err := json.Unmarshal(content, &opts); err != nil {
			o.t.Errorf("failed to unmarshal recordset update: %v", err)
		}

		o.Updates = append(o.Updates, ZoneUpdate{ZoneID: zoneID, Opts: opts})

		w.WriteHeader(http.StatusAccepted)
		if _, err := w.Write([]byte("{}")); err != nil {
			o.t.Errorf("failed to write recordset response: %v", err)
		}
		return
	}

	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/dns/v2/zones") && strings.Contains(r.URL.Path, "/recordsets") {
		slog.Info("matched get recordset mock response")

		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 5 {
			o.t.Errorf("invalid recordset get URL, too short: %s", r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		zoneID := parts[4]
		recordSetName := r.URL.Query().Get("name")
		recordSetType := r.URL.Query().Get("type")

		var matchingRecordSets = make([]MockRecordSet, 0)

		for idx, recordSet := range o.RecordSets {
			if recordSet.Name == recordSetName && recordSet.Type == recordSetType && recordSet.ZoneID == zoneID {
				matchingRecordSets = append(matchingRecordSets, o.RecordSets[idx])
			}
		}

		slog.Info("finished matching recordsets", "count", len(matchingRecordSets))

		var enrichedRecordSets []map[string]interface{}
		for _, rs := range matchingRecordSets {
			enrichedRecordSets = append(enrichedRecordSets, map[string]interface{}{
				"id":      rs.ID,
				"name":    rs.Name,
				"type":    rs.Type,
				"records": rs.Records,
				"zone_id": rs.ZoneID,
			})
		}

		resp := map[string]interface{}{
			"recordsets": enrichedRecordSets,
			"links":      map[string]string{"self": fmt.Sprintf("http://%s%s", r.Host, r.URL.String())},
			"metadata":   map[string]interface{}{"total_count": len(matchingRecordSets)},
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			o.t.Error("failed to write recordsets response")
		}
		return
	}

	if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/dns/v2/zones") && strings.Contains(r.URL.Path, "/recordsets") {
		slog.Info("matched delete recordset mock")

		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 7 {
			o.t.Errorf("invalid recordset get URL, too short: %s", r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		zoneID := parts[4]
		recordSetID := parts[6]

		o.RecordSetDeletes = append(o.RecordSetDeletes, RecordSetDelete{
			ZoneID:      zoneID,
			RecordSetID: recordSetID,
		})
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/dns/v2/zones") && strings.Contains(r.URL.Path, "/recordsets") {
		slog.Info("matched put recordset mock")

		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 7 {
			o.t.Errorf("invalid recordset get URL, too short: %s", r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		zoneID := parts[4]
		recordSetID := parts[6]

		var opts recordsets.UpdateOpts
		if err := json.Unmarshal(content, &opts); err != nil {
			o.t.Errorf("failed to unmarshal recordset update: %v", err)
		}

		o.RecordSetPuts = append(o.RecordSetPuts, RecordSetPut{
			ZoneID:      zoneID,
			RecordSetID: recordSetID,
			Opts:        opts,
		})
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("{}")); err != nil {
			o.t.Errorf("failed to write recordset response: %v", err)
		}
		return
	}
}

func CreateMockOpenstackApi(t *testing.T) *OpenstackApiMock {
	return &OpenstackApiMock{
		t: t,
	}
}
