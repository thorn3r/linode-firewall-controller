/*
Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	ktypes "k8s.io/apimachinery/pkg/types"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/linode/linodego"
	networkingv1alpha1 "github.com/thorn3r/linode-firewall-controller/api/v1alpha1"
)

const (
	annLinodeFirewallID = "networking.linode.com/linode-firewall-id"
	firewallAccept      = "ACCEPT"
	firewallDrop        = "DROP"
)

// ClusterwideNetworkPolicyReconciler reconciles a ClusterwideNetworkPolicy object
type ClusterwideNetworkPolicyReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	LinodeClient *linodego.Client
}

//+kubebuilder:rbac:groups=networking.linode.com,resources=clusterwidenetworkpolicies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networking.linode.com,resources=clusterwidenetworkpolicies/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=networking.linode.com,resources=clusterwidenetworkpolicies/finalizers,verbs=update
//+kubebuilder:rbac:groups=v1,resources=nodes,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.13.0/pkg/reconcile
func (r *ClusterwideNetworkPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	log.Info("triggering reconcile")

	var cwnp networkingv1alpha1.ClusterwideNetworkPolicy
	var firewall *linodego.Firewall

	if err := r.Get(ctx, req.NamespacedName, &cwnp); err != nil {
		log.Error(err, "unable to fetch ClusterwideNetworkPolicy")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if cwnp.ObjectMeta.Annotations == nil {
		cwnp.ObjectMeta.Annotations = make(map[string]string)
	}

	// fetch all nodes from the cluster
	var clusterNodes corev1.NodeList
	if err := r.List(ctx, &clusterNodes); err != nil {
		log.Error(err, "unable to fetch cluster Nodes")
		return ctrl.Result{}, err
	}

	// parse cluster ID from node name
	if len(clusterNodes.Items) < 1 {
		return ctrl.Result{}, nil
	}

	clusterLabel := strings.Split(clusterNodes.Items[0].Name, "-")[0]

	// parse Linode IDs from Node labels
	// TODO: fetch Linodes from API with cluster ID
	linodeIDs, err := LinodeIDsForCluster(ctx, r.LinodeClient, clusterLabel)
	if err != nil {
		log.Error(err, "unable to fetch Linodes for Cluster", "cluster", clusterLabel)
		return ctrl.Result{}, err
	}

	firewallIDAnnotation, ok := cwnp.Annotations[annLinodeFirewallID]
	if !ok || firewallIDAnnotation == "" {
		log.Info("debug", "firewallIDAnnotation", firewallIDAnnotation)
		// Create new Linode Firewall if ID annotation is not found
		var err error

		//TODO: CreatFirewallIfNotExists
		log.Info("creating new firewall")
		firewall, err = r.LinodeClient.CreateFirewall(
			ctx,
			linodego.FirewallCreateOptions{
				Label: fmt.Sprintf("%s-%d", clusterLabel, time.Now().Unix()),
				Devices: linodego.DevicesCreationOptions{
					Linodes: linodeIDs,
				},
				Rules: linodego.FirewallRuleSet{InboundPolicy: "ACCEPT", OutboundPolicy: "ACCEPT"},
			})
		if err != nil {
			log.Error(err, "unable to create Linode Firewall")
			return ctrl.Result{}, err
		}

		// set firewall ID annotation
		firewallIDAnnotation = strconv.Itoa(firewall.ID)
		cwnp.ObjectMeta.Annotations[annLinodeFirewallID] = firewallIDAnnotation
		log.Info("debug setting fw id annotation", "annotation", strconv.Itoa(firewall.ID))
		if err := r.Update(ctx, &cwnp); err != nil {
			log.Error(err, "unable to set firewall ID annotation on ClusterwideNetworkPolicy")
		}
		// update ClusterwideNetworkPolicy Status
		cwnp.Status.Firewall = networkingv1alpha1.Firewall{Id: int32(firewall.ID), Label: firewall.Label}
		if err := r.Status().Update(ctx, &cwnp); err != nil {
			log.Error(err, "unable to update ClusterwideNetworkPolicy status")
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}

	// fetch Firewall from Linode API and update Status
	firewallID, err := strconv.Atoi(firewallIDAnnotation)
	if err != nil {
		log.Error(err, "unable to parse FirewallID annotation to int")
		return ctrl.Result{}, err
	}
	firewall, err = r.LinodeClient.GetFirewall(ctx, firewallID)
	if err != nil {
		log.Error(err, "unable to fetch Firewall from Linode API")
		// clear Firewall ID annotation and requeue
		cwnp.Annotations[annLinodeFirewallID] = ""
		if err := r.Update(ctx, &cwnp); err != nil {
			log.Error(err, "unable to remove FirewallID annotation")
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}

	cwnp.Status.Firewall = networkingv1alpha1.Firewall{Id: int32(firewall.ID), Label: firewall.Label}
	if err := r.Status().Update(ctx, &cwnp); err != nil {
		log.Error(err, "unable to update ClusterwideNetworkPolicy status")
		return ctrl.Result{}, err
	}

	// Fetch list of devices (Linodes) associated with the Firewall
	devices, err := r.LinodeClient.ListFirewallDevices(ctx, firewallID, &linodego.ListOptions{})
	if err != nil {
		log.Error(err, "unable to list Firewall devices", "firewall", firewallID)
		return ctrl.Result{}, err
	}

	// Add any missing Nodes to the Firewall as devices
	log.Info("debug: reconciling nodes", "linodeIDs", linodeIDs, "devices", devices)
	err = r.ReconcileNodes(ctx, firewallID, linodeIDs, devices)
	if err != nil {
		log.Error(err, "unable to reconcile nodes")
		return ctrl.Result{}, err
	}

	// Reconcile Firewall Rules
	var firewallRules linodego.FirewallRuleSet
	if len(cwnp.Spec.Ingress) == 0 {
		firewallRules.InboundPolicy = firewallAccept
	} else {
		firewallRules.InboundPolicy = firewallDrop
	}
	if len(cwnp.Spec.Egress) == 0 {
		firewallRules.OutboundPolicy = firewallAccept
	} else {
		firewallRules.OutboundPolicy = firewallDrop
	}

	for _, rule := range cwnp.Spec.Ingress {
		for _, addr := range rule.From {
			for _, port := range rule.Ports {
				newRule := linodego.FirewallRule{
					Action:    firewallAccept,
					Ports:     port.Port.String(),
					Protocol:  linodego.NetworkProtocol(*port.Protocol),
					Addresses: linodego.NetworkAddresses{IPv4: &[]string{addr.CIDR}},
					Label:     fmt.Sprintf("port%s-%s", port.Port.String(), strings.Replace(addr.CIDR, "/", "_", -1)),
				}
				firewallRules.Inbound = append(firewallRules.Inbound, newRule)
				//firewallRules.InboundPolicy = firewallDrop
			}
		}
	}

	for _, rule := range cwnp.Spec.Egress {
		for _, addr := range rule.To {
			for _, port := range rule.Ports {
				newRule := linodego.FirewallRule{
					Action:    firewallAccept,
					Ports:     port.Port.String(),
					Protocol:  linodego.NetworkProtocol(*port.Protocol),
					Addresses: linodego.NetworkAddresses{IPv4: &[]string{addr.CIDR}},
					Label:     fmt.Sprintf("port%s-%s", port.Port.String(), strings.Replace(addr.CIDR, "/", "_", -1)),
				}
				firewallRules.Outbound = append(firewallRules.Outbound, newRule)
			}
		}
	}

	// TODO: force allow IPIP traffic over private network, as calico overlay network needs this
	// the Linode API added support for IPENAP, linodego has not yet been updated

	if _, err = r.LinodeClient.UpdateFirewallRules(ctx, firewallID, firewallRules); err != nil {
		log.Error(err, "unable to update Firewall rules", "firewallRules", firewallRules)
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *ClusterwideNetworkPolicyReconciler) ReconcileNodes(ctx context.Context, firewallID int, linodeIDs []int, devices []linodego.FirewallDevice) error {
	// TODO: make this more efficient than O(n^2)
	log := log.FromContext(ctx)

	// add any missing nodes
	for _, linodeID := range linodeIDs {
		exists := false
		for _, device := range devices {
			if device.Entity.ID == linodeID {
				exists = true
				break
			}
		}
		if !exists {
			log.Info("debug adding node to firewall", "linodeID", linodeID)
			createOpts := linodego.FirewallDeviceCreateOptions{
				ID:   linodeID,
				Type: linodego.FirewallDeviceLinode,
			}
			_, err := r.LinodeClient.CreateFirewallDevice(ctx, firewallID, createOpts)
			if err != nil {
				log.Error(err, "unable to create Firewall Device", "firewall", firewallID, "linodeID", linodeID)
				return err
			}
		}
	}

	// remove any delete nodes
	for _, device := range devices {
		exists := false
		for _, linodeID := range linodeIDs {
			if device.Entity.ID == linodeID {
				exists = true
				break
			}
		}
		if !exists {
			log.Info("debug removing node from firewall", "deviceID", device.Entity.ID)
			err := r.LinodeClient.DeleteFirewallDevice(ctx, firewallID, device.Entity.ID)
			if err != nil {
				log.Error(err, "unable to delete Firewall Device", "firewall", firewallID, "device", device.Entity.ID)
				return err
			}
		}
	}
	return nil
}

// findClusterwideNetworkPolicies returns a list containing 1 reconcile.Request
// for every ClusterwidNetowrkPolicy that exists in the cluster. This is
// necessary to trigger updates to
func (r *ClusterwideNetworkPolicyReconciler) findClusterwideNetworkPolicies(obj client.Object) []reconcile.Request {
	var cwnpList networkingv1alpha1.ClusterwideNetworkPolicyList
	var requests []reconcile.Request
	ctx := context.Background()
	log := log.FromContext(ctx)

	if err := r.List(ctx, &cwnpList); err != nil {
		log.Error(err, "unable to fetch list of ClusterwideNetworkPolicies")
		return requests
	}
	for _, cwnp := range cwnpList.Items {
		requests = append(requests, reconcile.Request{NamespacedName: ktypes.NamespacedName{Namespace: cwnp.Namespace, Name: cwnp.Name}})
	}
	return requests
}

// SetupWithManager sets up the controller with the Manager.
func (r *ClusterwideNetworkPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&networkingv1alpha1.ClusterwideNetworkPolicy{}).
		Watches(
			&source.Kind{Type: &corev1.Node{}},
			// TODO: filter out Node update events
			handler.EnqueueRequestsFromMapFunc(r.findClusterwideNetworkPolicies),
		).
		Complete(r)
}

func LinodeIDsForCluster(ctx context.Context, client *linodego.Client, clusterLabel string) ([]int, error) {
	var nodeIDs []int
	// remove 'lke' prefix from cluster label
	idStr := strings.Split(clusterLabel, "lke")[1]
	clusterID, err := strconv.Atoi(idStr)
	if err != nil {
		return nodeIDs, err
	}
	nodePools, err := client.ListLKENodePools(ctx, clusterID, &linodego.ListOptions{})
	if err != nil {
		return nodeIDs, err
	}
	for _, pool := range nodePools {
		for _, node := range pool.Linodes {
			nodeIDs = append(nodeIDs, node.InstanceID)
		}
	}
	return nodeIDs, nil
}
