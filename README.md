# RBAC API Utils
[![License](https://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)

A library for fine-grained multi-cluster RBAC API. Access control in OCM is based on RBAC contructs  provided by Kubernetes,
this library provides utiilies and  wrappers around the Kubernetes RBAC API for convenience and 
to achieve finer grained access control.

Go to the [Contributing guide](CONTRIBUTING.md) to learn how to get involved.

## Usage

To get started, create an instance of the AccessReviewer as below:

```go

import (
  "github.com/stolostron/rbac-api-utils/rbac"
)

// Create an instance of AccessReviewer with the KubeConfig for the target cluster
accessReviewer := rbac.NewAccessReviewer(myTargetKubeConfig, nil)

```

See [here](./pkg/rbac/rbac.go/#L49) for more information on the parameters for creation of an AccessReviewer

### Supported API

**GetMetricsAccess** returns the  managed clusters and namespaces on the managed clusters for which the user has access to view observability metrics. See [here](./pkg/rbac/rbac.go/#L121) for details on the input parameters and results.


OCM Observability gathers  metrics from the managed clusters and stores them for viewing on the Hub. Users can be given access to view metrics for specific namespaces on specific managed clusters.

Consider the scenario where an application "Blue" is deloyed to namespaces blue1 and blue2 on managed clusters  devcluster1 and devcluster2. Inorder to give the Blue admins  access to view Blue metrics, the following cluster roles are set

```yaml
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: view-blue-metrics
rules:
  - apiGroups:
      - "cluster.open-cluster-management.io"
    resources:
      - managedclusters
    resourceNames:
      - devcluster1
      - devcluster2
    verbs:
      - metrics/blue1
      - metrics/blue2
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: view-blue-metrics-binding
subjects:
  - kind: Group
    apiGroup: rbac.authorization.k8s.io
    name: blue-admins
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: view-blue-metrics
---
```
A call to **GetMetricsAccess** for a user in the blue-admins group, will return the following results

- All allowed clusters
    GetMetricsAccess("blueuserToken")  - { "devcluster1": [ "blue1", "blue2"] , "devcluster2": ["blue1", "blue2"] }

- Specific clusters 
    GetMetricsAccess("blueuserToken", "devcluster1")  - { "devcluster1": [ "blue1", "blue2"]}