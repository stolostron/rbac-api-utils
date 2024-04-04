// Package rbac provides various Access Review API
package rbac

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/exp/slices"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog"
)

// ACLConfig holds the  access control configuration  needed to  perform an action
// e.g. "get" permission on the  "managedclusters" resource is needed to "view" a managedcluster on the ACM Hub.
// The configuration includes ApiGroup, Resource type but not Version as rules in K8s ClusterRole
// do not include/specify version.
type ACLConfig struct {
	// groupRes is the API Group and Resource information
	groupRes schema.GroupResource
	// verb is the action on the Resource
	verb string
}

// MetricsACLConfig is an instance of ACLConfig and holds configuration for accessing observability
// metrics gathered from ManagedClusters
var MetricsACLConfig = ACLConfig{
	groupRes: schema.GroupResource{
		Group:    "cluster.open-cluster-management.io",
		Resource: "managedclusters",
	},
	verb: "metrics/",
}

// AccessReviewer is the  API for custom fined-grained access control, it holds the
// configuration needed to connect to the Kubernetes cluster to retrieve user's access information.
// It must be instantiated through the NewAccessReviewer function as it will do any required validation.
type AccessReviewer struct {
	kubeConfig *rest.Config
	kubeClient kubernetes.Interface
}

// NewAccessReviewer creates an instance of AccessReviewer.
// It takes two parameters kConfig and kClient, but expects a value to be set for only one of them.
// An error will be thrown if neither or both values are set.
//
// - kConfig is k8s cluster configuration. This should be set when API consumer intends to use
// the AccessReviewer instance to retrieve ACLs for different users. User specific details(i.e Token)
// would need to be passed to every invocation of access review API, which will be used to create a
// k8s client to connect to the cluster to retrieve user specific ACLs.
//
// - kClient is K8s cluster client. This should be set when API consumer intends to use
// the AccessReviewer instance for a single user. The provided k8s client connection will be directly
// used to fetch ACLs from the cluster. In this case, access review  API can be invoked without needing
// to pass the user's Token on every call.
func NewAccessReviewer(kConfig *rest.Config, kClient kubernetes.Interface) (*AccessReviewer, error) {
	// Verify only one of k8s config or client are set
	if kClient == nil && kConfig == nil {
		return nil, errors.New("one of either kubeConfig or kubeClient must be a non-nil value")
	}

	if kClient != nil && kConfig != nil {
		return nil, errors.New("only one of either kubeConfig or kubeClient must be a non-nil value")
	}

	accessReviewer := new(AccessReviewer)

	if kConfig != nil {
		configCopy := *kConfig
		accessReviewer.kubeConfig = &configCopy
	} else {
		accessReviewer.kubeClient = kClient
	}

	return accessReviewer, nil
}

// getKubeClientForUser returns the k8s client to use to connect to the cluster.
// - userToken is the user's OAuth bearer token.  It will be used along with the k8sConfig,
// set on the AccessReviewer, to create a new k8s client. If k8sConfig is not available,
// then the configured k8s client is returned.
func (r *AccessReviewer) getKubeClientForUser(userToken string) (kubernetes.Interface, error) {
	if r.kubeConfig != nil {
		// if a valid userToken
		if userToken != "" {
			// make a copy of the RestConfig to avoid overwrites when multiple api calls are made in parallel
			userKubeConfig := &rest.Config{
				Host:    r.kubeConfig.Host,
				APIPath: r.kubeConfig.APIPath,
				TLSClientConfig: rest.TLSClientConfig{
					CAFile:     r.kubeConfig.TLSClientConfig.CAFile,
					CAData:     r.kubeConfig.TLSClientConfig.CAData,
					ServerName: r.kubeConfig.TLSClientConfig.ServerName,
					// For testing
					Insecure: r.kubeConfig.TLSClientConfig.Insecure,
				},
			}

			// tokenfile takes precedence over token,
			// set tokenfile to empty to ensure token is used
			userKubeConfig.BearerTokenFile = ""
			userKubeConfig.BearerToken = userToken
			// create the clientset
			kclient, err := kubernetes.NewForConfig(userKubeConfig)
			if err != nil {
				return nil, err
			}

			return kclient, nil
		}

		return nil, fmt.Errorf(
			"failed to get a client to connect to the kubernetes cluster:" +
				"When KubeConfig is provided, a valid userToken must be set on all access review calls")
	}

	// if kubeConfig isnt set then return the kubeClient set
	return r.kubeClient, nil
}

// GetMetricsAccess retrieves the user's ACLs from the k8s cluster  and processes them to determine
// user's access to observability metrics that are gathered from managed clusters.
// It returns a map where the keys are managed clusters and the values are slices of allowed namespaces.
//
// - userToken is the user's OAuth bearer token, is required if k8s config was set on the AccessReviewer
//
// - clusters are the  names of the managed clusters for which  allowed metrics access is returned.
// If no clusters are specified, then  metrics access is returned for all "allowed" managed clusters.
func (r *AccessReviewer) GetMetricsAccess(userToken string, clusters ...string) (map[string][]string, error) {
	klog.V(2).Infof("GetMetricsAccess for clusters: %v", clusters)

	// get Client to talk to the Kubernetes cluster
	userKClient, err := r.getKubeClientForUser(userToken)
	if err != nil {
		return nil, err
	}

	// get all user ACLs on ManagedCluster resources
	resourceACLs, err := GetResourceAccess(userKClient, MetricsACLConfig.groupRes, clusters, "")
	if err != nil {
		return nil, err
	}

	klog.V(2).Infof(" resource access results: %v", resourceACLs)

	// from the list of all ACLs for ManagedCluster, filter out the "metrics" specific acls and grab the namespaces
	metricsAccessResults := make(map[string][]string, len(resourceACLs))

	for clustername, clusteracls := range resourceACLs {
		klog.V(2).Infof("clustername [%s] acls[%s]\n", clustername, clusteracls)

		// list of namespaces for the cluster
		metricsAccessMap := make(map[string]bool, len(clusteracls))

		for _, acl := range clusteracls {
			// filter verbs that start with metrics/ and grab the namespace
			// if verb is set to *, set namespace to * to indicate access to all namespaces
			if strings.HasPrefix(acl, MetricsACLConfig.verb) {
				metricsAccessMap[strings.TrimPrefix(acl, MetricsACLConfig.verb)] = true
			} else if acl == "*" {
				metricsAccessMap["*"] = true
			}
		}

		nsWithMetricsAccess := make([]string, 0, len(metricsAccessMap))
		for ns := range metricsAccessMap {
			nsWithMetricsAccess = append(nsWithMetricsAccess, ns)
		}

		klog.V(2).Infof("clustername [%s], Namespaces with metrics access[%s]\n", clustername, nsWithMetricsAccess)

		// add cluster to returned map if metrics acls are set for it
		if len(nsWithMetricsAccess) > 0 || slices.Contains(clusters, clustername) {
			metricsAccessResults[clustername] = nsWithMetricsAccess
		}
	}

	klog.V(2).Infof(" metricsAccessResults is %v", metricsAccessResults)

	return metricsAccessResults, nil
}

// GetResourceAccess returns all configured ACLs for a given resource type.
// It returns a map of resource names and ACLs for that resource. for a given resource,
// if no  ACLs are configured, an empty list is returned for it in the results.
//
// - resourcenames are the names of the resources for which ACLs are and returned,
// if no resource names are passed, ACLs for all allowed resources of the given type are returned.
//
// - namespace is used for namespace-scoped resources, for cluster-scoped resources it should be left empty.
// If not specified, it defaults to the value "default" for namespace-scoped resources.
func GetResourceAccess(
	kclient kubernetes.Interface, gr schema.GroupResource, resourcenames []string, namespace string,
) (map[string][]string, error) {
	klog.V(2).Infof(
		"GetResourceAccess for GroupResource: %s, resourcenames: %v, namespace: %s", gr, resourcenames, namespace)

	// make a SelfSubjectRulesReview to get all resource rules.
	resourceRules, err := makeSubjectRulesReviewForUser(kclient, namespace)
	if err != nil {
		return nil, err
	}

	resourceAccessResults := make(map[string][]string)
	// search through all the resource rules
	for _, rule := range resourceRules {
		// each resource rule contains { []ApiGroup, []Resources, []ResourceNames, []Verbs}
		// e.g: {[metrics/nsred1 metrics/nsred2] [cluster.open-cluster-management.io]
		// [managedclusters] [devcluster1 devcluster2]}
		// filter the rules by the given ApiGroup(or *) and Resource(or *))
		ruleMatchesAPIGroup := (slices.Contains(rule.APIGroups, gr.Group) || slices.Contains(rule.APIGroups, "*"))
		ruleMatchesResource := (slices.Contains(rule.Resources, gr.Resource) || slices.Contains(rule.Resources, "*"))

		if !(ruleMatchesAPIGroup && ruleMatchesResource) {
			continue
		}

		klog.V(2).Infof("Found Rule that matches the given GroupResource %v", rule)

		// if a set of resource names are included in the rule, then add the acls only for those resources names
		if len(rule.ResourceNames) != 0 {
			for _, ruleResourceName := range rule.ResourceNames {
				// if given resourcenames is empty or contains the resourcename in the rule,
				//  apply rule to that resourcename
				if len(resourcenames) == 0 || slices.Contains(resourcenames, ruleResourceName) {
					// add verbs that are not already in the list
					resourceAccessResults[ruleResourceName] = addUniqueItems(
						resourceAccessResults[ruleResourceName], rule.Verbs...)
				}
			}
		} else {
			// if no resource names are set on the rule, it means acls in it apply to all resources of this type
			if len(resourcenames) != 0 {
				// if given resourcenames is nonempty,
				// add acls to  each of the resourcename as the rule appplies to all  of the type
				for _, rname := range resourcenames {
					// add verbs that are not already in the list
					resourceAccessResults[rname] = addUniqueItems(resourceAccessResults[rname], rule.Verbs...)
				}
			} else {
				// if given resourcenames is empty,  add acls under the "*" entry as rule applied to all
				resourceAccessResults["*"] = addUniqueItems(resourceAccessResults["*"], rule.Verbs...)
			}
		}
	}

	// the above only adds entries for the resourcenames that have some acls associated with it
	// so add empty entries for any resourcenames that are missing in the result list
	if len(resourcenames) != 0 {
		for _, rname := range resourcenames {
			if _, ok := resourceAccessResults[rname]; !ok {
				resourceAccessResults[rname] = []string{}
			}
		}
	}

	klog.V(2).Infof("Resource access results %v", resourceAccessResults)

	return resourceAccessResults, nil
}

// addUniqueItems a convenience method for building a slice with unique entries
// specified items are added to the given slice of items if not already in it
func addUniqueItems(itemlist []string, itemsToAdd ...string) []string {
	klog.V(2).Infof("Adding items %v to list %v", itemsToAdd, itemlist)

	// iterate through each of the items in  itemsToAdd list
	// and add item only if it doesnt already exist in the itemlist
	resultList := itemlist
	for _, item := range itemsToAdd {
		// check if itemList  contains the item before appending
		if !slices.Contains(resultList, item) {
			resultList = append(resultList, item)
		}
	}

	klog.V(3).Infof("Result List: %v ", resultList)

	return resultList
}

// makeSubjectRulesReviewForUser is a helper function that makes a SelfSubjectRulesReview call
// on the k8s cluster. If the call is successful then it returns a slice of all ResourceRules
// configured for the user.
//
// - namespace is the namespace to set  in the selfsubjectaccessreview call, if not specified
// it defaults to an invalid namespace to limit the response to cluster scoped resources.
func makeSubjectRulesReviewForUser(
	kclient kubernetes.Interface, namespace string,
) ([]authorizationv1.ResourceRule, error) {
	klog.V(2).Infof("Make Subject Access Rules Review for Namespace %s", namespace)

	// selfsubjectaccessreview needs to be  for a specific namespace
	// It returns ResourceRules for all allowed namespace-scoped resources in the given namespace
	// +  all allowed cluster-scoped resources
	// When the user's bearer token is used to make the call instead of  user impersonation,
	// the user's usergroup info is already taken into account when returning the acls
	// if the call is successful then this function returns a list of resourcerules

	if namespace == "" {
		// This is a workaround for SelfSubjectRulesReview errantly accepting RoleBindings on the default namespace
		// for cluster scoped access. Only ClusterRoleBindings actually affect access.
		namespace = "$ Invalid $"
	}

	sarr := &authorizationv1.SelfSubjectRulesReview{
		Spec: authorizationv1.SelfSubjectRulesReviewSpec{
			Namespace: namespace,
		},
	}

	response, err := kclient.AuthorizationV1().SelfSubjectRulesReviews().Create(
		context.TODO(), sarr, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	sarrStatus := response.Status

	// Log the evaluation error but don't block since partial results is better than completely failing.
	if sarrStatus.EvaluationError != "" {
		klog.Infof(
			"Encountered a SelfSubjectRulesReviews error in namespace %s: %v", namespace, sarrStatus.EvaluationError,
		)
	}

	klog.V(2).Infof("Resources Rule : %v", sarrStatus.ResourceRules)

	return sarrStatus.ResourceRules, nil
}
