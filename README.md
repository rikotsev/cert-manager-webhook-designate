# ACME webhook for Openstack's Designate API

---

To be used together with [cert-manager](https://cert-manager.io/). 
Loosely inspired by [this](https://github.com/syseleven/designate-certmanager-webhook) implementation.

## Requirements

---

- [go](https://go.dev/) >= 1.25.1 (if you want to contribute)

## Installation

### Helm

```bash
helm install designate-webhook deploy/designate-webhook -n cert-manager
```

## Configuration

### 1. Create Credentials Secret

Create a Kubernetes Secret containing your OpenStack Application Credentials.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: openstack-designate-credentials
  namespace: cert-manager
type: Opaque
stringData:
  tenantName: "testTenant"
  tenantId: "testTenantId"
  domainName: "testDomainName"
  domainId: "testDomainId"
  username: "john-doe"
  password: "secretpass"
  identityEndpoint: "https://identity.api.openstack.org/v3"
  region: "RegionOne"
```

### 2. Create Issuer

Create a cert-manager `Issuer` or `ClusterIssuer` that references the webhook and the secret created above.

```yaml
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: designate-issuer
spec:
  acme:
    email: your-email@example.com
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: letsencrypt-staging-account-key
    solvers:
    - dns01:
        webhook:
          groupName: designate.cert-manager-webhook.rikotsev
          solverName: openstack-designate
          config:
            secretName: openstack-designate-credentials
            secretNamespace: cert-manager
            strategy:
              kind: BestEffort
```

## Strategies

The webhook supports different strategies for determining which OpenStack Designate Zone to use for the challenge record.

### `BestEffort` (Recommended)
Scans all available zones in the project and selects the one that best matches the challenge FQDN (longest suffix match).

### `SOA`
Uses the SOA record of the resolved zone to determine the correct Designate zone ID.

### `ZoneName`
Explicitly forces the use of a specific zone name.

```yaml
          config:
            # ...
            strategy:
              kind: ZoneName
              zoneName: example.com.
```