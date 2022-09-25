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

package v1alpha1

import (
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ClusterwideNetworkPolicySpec defines the desired state of ClusterwideNetworkPolicy
type ClusterwideNetworkPolicySpec struct {
	// List of Ingress Rules to be applied to the Linode Firewall
	// +optional
	Ingress []IngressRule `json:"ingress,omitempty"`

	// List of Egress Rules to be applied to the Linode Firewall
	// +optional
	Egress []EgressRule `json:"egress,omitempty"`
}

type IngressRule struct {
	// List of sources to allow Ingress from
	// +optional
	From []networkingv1.IPBlock `json:"from,omitempty"`

	// List of source ports to allow Ingress from
	// +optional
	Ports []networkingv1.NetworkPolicyPort `json:"ports,omitempty"`
}

type EgressRule struct {
	// List of destinations to allow Egress to
	// +optional
	To []networkingv1.IPBlock `json:"to,omitempty"`

	// List of destination ports to allow Egress to
	// +optional
	Ports []networkingv1.NetworkPolicyPort `json:"ports,omitempty"`
}

// ClusterwideNetworkPolicyStatus defines the observed state of ClusterwideNetworkPolicy
type ClusterwideNetworkPolicyStatus struct {
	// The Linode Firewall backing the ClusterwideNetworkPolicy
	// +optional
	Firewall Firewall `json:"firewall,omitempty"`
}

type Firewall struct {
	//+kubebuilder:validation:Minimum=0
	// The ID of the Linode Firewall
	Id int32 `json:"id"`

	//+kubebuilder:validation:MinLength=0
	// The label of the Linode Firewall
	Label string `json:"label"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:shortName=cwnp

// ClusterwideNetworkPolicy is the Schema for the clusterwidenetworkpolicies API
type ClusterwideNetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterwideNetworkPolicySpec   `json:"spec,omitempty"`
	Status ClusterwideNetworkPolicyStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// ClusterwideNetworkPolicyList contains a list of ClusterwideNetworkPolicy
type ClusterwideNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterwideNetworkPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ClusterwideNetworkPolicy{}, &ClusterwideNetworkPolicyList{})
}
