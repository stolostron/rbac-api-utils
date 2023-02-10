package rbac

import (
	"context"
	"os"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

const blueMetricsAccessYaml = `
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
      - metrics/nsblue1
      - metrics/nsblue2
      - metrics/nsblue3
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
`

const redMetricsAccessYaml = `
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: view-red-metrics
rules:
  - apiGroups:
      - "cluster.open-cluster-management.io"
    resources:
      - managedclusters
    resourceNames:
      - devcluster1
      - devcluster2
    verbs:
      - metrics/nsred1
      - metrics/nsred2
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: view-red-metrics-binding
subjects:
  - kind: Group
    apiGroup: rbac.authorization.k8s.io
    name: red-admins
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: view-red-metrics
---
`

const systemMetricsAccessOnAllClusterYaml = `
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: view-system-metrics
rules:
  - apiGroups:
      - "cluster.open-cluster-management.io"
    resources:
      - managedclusters
    verbs:
      - metrics/kube-system
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: view-system-metrics-binding
subjects:
  - kind: Group
    apiGroup: rbac.authorization.k8s.io
    name: system-admins
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: view-system-metrics
---
`

const NonMetricAcls = `
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: listcusters
rules:
  - apiGroups:
      - "cluster.open-cluster-management.io"
    resources:
      - managedclusters
    verbs:
      - list
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: listclusters-binding
subjects:
  - kind: Group
    apiGroup: rbac.authorization.k8s.io
    name: cluster-listers
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: listclusters
---
`

var (
	baseK8sConfig *rest.Config
	baseK8sClient kubernetes.Interface
	testEnv       *envtest.Environment
	ctx           context.Context
	cancel        context.CancelFunc
	testUsers     = map[string]struct {
		KubeClient kubernetes.Interface
		Groups     []string
	}{
		"user-blue": {
			nil, // set after startUp
			[]string{"blue-admins"},
		},
		"user-red": {
			nil, // set after startUp
			[]string{"red-admins"},
		},
		"user-purple": {
			nil, // set after startUp
			[]string{"blue-admins", "red-admins"},
		},
		"user-no-specific-access": {
			nil, // set after startUp
			[]string{"no-specific-access"},
		},
		"user-sysadmin": {
			nil, // set after startUp
			[]string{"system-admins"},
		},
		"user-clusterlister": {
			nil, // set after startUp
			[]string{"cluster-listers"},
		},
	}
	testRbacResourceYamls = []string{blueMetricsAccessYaml, redMetricsAccessYaml, systemMetricsAccessOnAllClusterYaml}
)

func TestMain(m *testing.M) {
	os.Exit(testMain(m))
}

func testMain(m *testing.M) int {
	defer tearDown()

	setUp()

	return m.Run()
}

func setUp() {
	testEnv = &envtest.Environment{}

	var err error

	baseK8sConfig, _ = testEnv.Start()

	baseK8sClient, err = kubernetes.NewForConfig(baseK8sConfig)
	if err != nil {
		panic(err.Error())
	}

	ctx, cancel = context.WithCancel(context.TODO())

	// SetUp Users and their Groups
	for user, userConfig := range testUsers {
		userKubeClient, err := SetupUser(user, userConfig.Groups)
		if err != nil {
			panic(err.Error())
		}

		userConfig.KubeClient = userKubeClient
		testUsers[user] = userConfig
	}

	// Setup RBAC resources for MetricsAccess
	for _, testRbacResourceYaml := range testRbacResourceYamls {
		err = SetupRBACResources(testRbacResourceYaml)
		if err != nil {
			panic(err.Error())
		}
	}
}

func tearDown() {
	cancel()

	err := testEnv.Stop()
	if err != nil {
		panic(err.Error())
	}
}

func SetupUser(username string, groups []string) (kubernetes.Interface, error) {
	user := envtest.User{
		Name:   username,
		Groups: groups,
	}

	testUser, err := testEnv.AddUser(user, baseK8sConfig)
	if err != nil {
		return nil, err
	}

	testUserKClient, err := kubernetes.NewForConfig(testUser.Config())
	if err != nil {
		return nil, err
	}

	return testUserKClient, nil
}

func SetupRBACResources(resourcesYaml string) error {
	decode := scheme.Codecs.UniversalDeserializer().Decode

	singleResourceYamls := strings.Split(resourcesYaml, "---")

	for _, singleRes := range singleResourceYamls {
		if singleRes == "\n" || singleRes == "" {
			continue
		}

		obj, _, err := decode([]byte(singleRes), nil, nil)
		if err != nil {
			return err
		}

		switch obj := obj.(type) {
		case *rbacv1.ClusterRole:
			_, err = baseK8sClient.RbacV1().ClusterRoles().Create(ctx, obj, metav1.CreateOptions{})
			if err != nil {
				return err
			}

		case *rbacv1.ClusterRoleBinding:
			_, err = baseK8sClient.RbacV1().ClusterRoleBindings().Create(ctx, obj, metav1.CreateOptions{})
			if err != nil {
				return err
			}
		}
	}

	return nil
}
