package rbac

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/exp/slices"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func TestNewAccessReviewer(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		kubeClient  kubernetes.Interface
		kubeConfig  *rest.Config
		expectedErr error
	}{
		{nil, baseK8sConfig, nil},
		{baseK8sClient, nil, nil},
		{
			nil,
			nil,
			errors.New("one of either kubeConfig or kubeClient must be a non-nil value"),
		},
		{
			baseK8sClient,
			baseK8sConfig,
			errors.New("only one of either kubeConfig or kubeClient must be a non-nil value"),
		},
	}

	for _, test := range testcases {
		_, err := NewAccessReviewer(test.kubeConfig, test.kubeClient)
		if !(errors.Is(err, test.expectedErr) || strings.EqualFold(test.expectedErr.Error(), err.Error())) {
			t.Fatalf("expected err: %s got err: %s", test.expectedErr, err)
		}
	}
}

func TestGetMetricsAccess(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		username       string
		kubeClient     kubernetes.Interface
		inputClusters  []string
		expectedResult map[string][]string
		expectedErr    error
	}{
		{ // user-red is in red-admin usergroup, so has access to red namespaces 1 & 2 on devcluster 1 & 2
			"user-red",
			testUsers["user-red"].KubeClient,
			[]string{}, // get metrics access for all managed clusters
			map[string][]string{
				"devcluster1": {"nsred1", "nsred2"},
				"devcluster2": {"nsred1", "nsred2"},
			},
			nil,
		},
		{
			"user-red",
			testUsers["user-red"].KubeClient,
			[]string{"devcluster1"}, // get  metrics access for a single specific managedcluster
			map[string][]string{
				"devcluster1": {"nsred1", "nsred2"},
			},
			nil,
		},
		{
			"user-red",
			testUsers["user-red"].KubeClient,
			[]string{"devcluster1", "devcluster2"}, // get metrics access for multiple specific managedclusters
			map[string][]string{
				"devcluster1": {"nsred1", "nsred2"},
				"devcluster2": {"nsred1", "nsred2"},
			},
			nil,
		},
		{
			"user-red",
			testUsers["user-red"].KubeClient,
			[]string{"blah"}, // get metrics access for a managedcluster  "blah" for which user has  no acls set
			map[string][]string{
				"blah": {}, // should return an empty slice
			},
			nil,
		},
		{ // user-blue  is in blue-admin usergroup, so  has access to blue namespaces 1,2  &3 on devcluster 1 & 2
			"user-blue",
			testUsers["user-blue"].KubeClient,
			[]string{}, // all clusters
			map[string][]string{
				"devcluster1": {"nsblue1", "nsblue2", "nsblue3"},
				"devcluster2": {"nsblue1", "nsblue2", "nsblue3"},
			},
			nil,
		},
		{ // user-purple is in both blue-admin & red-admin usergroup,
			// so  has access to red ns 1,2 and blue ns 1,2,3 on devcluster 1 & 2
			"user-purple",
			testUsers["user-purple"].KubeClient,
			[]string{},
			map[string][]string{
				"devcluster1": {"nsblue1", "nsblue2", "nsblue3", "nsred1", "nsred2"},
				"devcluster2": {"nsblue1", "nsblue2", "nsblue3", "nsred1", "nsred2"},
			},
			nil,
		},
		{ // user-sysadmin  is in system-admin usergroup, so  has access to namespace kube-system on all clusters
			"user-sysadmin",
			testUsers["user-sysadmin"].KubeClient,
			[]string{}, // all clusters
			map[string][]string{
				"*": {"kube-system"},
			},
			nil,
		},
		{ // user-sysadmin  is in system-admin usergroup, so  has access to namespace kube-system on all clusters
			"user-sysadmin",
			testUsers["user-sysadmin"].KubeClient,
			[]string{"testcluster"}, // when a specific cluster is input,  result should contain  only that
			map[string][]string{
				"testcluster": {"kube-system"},
			},
			nil,
		},
		{ // cluster-admin should have rule *,*,*
			"cluster-admin",
			baseK8sClient,
			[]string{},
			map[string][]string{
				"*": {"*"},
			},
			nil,
		},
		{ // cluster listers should have no metrics acl entries
			"user-clusterlister",
			testUsers["user-clusterlister"].KubeClient,
			[]string{},
			map[string][]string{},
			nil,
		},
		{ // cluster listers should have no metrics acl entries
			"user-clusterlister",
			testUsers["user-clusterlister"].KubeClient,
			[]string{"devcluster1", "devcluster2"},
			map[string][]string{
				"devcluster1": {},
				"devcluster2": {},
			},
			nil,
		},
	}

	for _, test := range testcases {
		rbacEngine, err := NewAccessReviewer(nil, test.kubeClient)
		if err != nil {
			t.Fatalf(err.Error())
		}

		gotResult, err := rbacEngine.GetMetricsAccess("", test.inputClusters...)
		if err != nil {
			t.Fatalf(err.Error())
		}

		// compare  Received results to Expected Result
		if !compareMetricsAccessResults(test.expectedResult, gotResult) {
			t.Fatalf("expected result : %v , got  : %v", test.expectedResult, gotResult)
		}
	}
}

func compareMetricsAccessResults(expectedResults map[string][]string, gotResults map[string][]string) bool {
	// compare length
	if len(expectedResults) != len(gotResults) {
		return false
	}

	for expCluster, expNamespaces := range expectedResults {
		if gotNamespaces, ok := gotResults[expCluster]; ok {
			// clusterName exists in both, now compare namespaces
			for _, expNS := range expNamespaces {
				if !slices.Contains(gotNamespaces, expNS) {
					return false
				}
			}
		} else {
			return false
		}
	}

	return true
}

func TestMakeSubjectAccessRulesReviewForUser(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		username         string
		kubeClient       kubernetes.Interface
		namespace        string
		expectedNumRules int
	}{
		// every user has one basic rule - ability to create selfsubject  review
		// rest depends on the acl assigned to the user or user's group

		// basic rule + access to all */*/*
		{"cluster-admin", baseK8sClient, "", 2},
		// testing for a different namespace but the result is same as above
		{"cluster-admin", baseK8sClient, "testns", 2},
		// only the basic rule
		{"user-no-specific-access", testUsers["user-no-specific-access"].KubeClient, "", 1},
		// basic rule + access to red-metrics + access to blue-metrics
		{"user-purple", testUsers["user-purple"].KubeClient, "", 3},
	}

	for _, test := range testcases {
		accessrules, err := makeSubjectAccessRulesReviewForUser(test.kubeClient, "")
		if err != nil {
			t.Fatalf(err.Error())
		}

		if test.expectedNumRules != len(accessrules) {
			t.Fatalf("expected num of access rules : %d , got  : %d", test.expectedNumRules, len(accessrules))
		}
	}
}
