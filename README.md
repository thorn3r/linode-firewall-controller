# linode-firewall-controller
The linode-firewall-controller extends support for Linode Cloud Firewalls to LKE.

<img src="https://www.linode.com/wp-content/uploads/2020/05/icon-cloud-firewall-2c-1.svg" width=150>

### This API is in Alpha
As an alpha API, the resources are subject to breaking changes in the future.

TODO: Reduce volume of reconciliation events by filtering out updates to Node Status

TODO: Add support for IPIP traffic required for the calico overlay network. This is currently supported in the Linode API, but linodego support has not yet been added.

## Description

linode-firewall-controller is designed to run within an LKE cluster to extend support for Linode Cloud Firewalls. It implements a controller for a new CRD, ClusterwideNetworkPolicy, which allows a user to specify a set of egress and ingress rules to be applied to all cluster nodes at layer3/4 (IPIP support coming soon). For each ClusterwideNetworkPolicy, a Linode Cloud Firewall is provisioned and configured to the specifications. When Kuberenetes Nodes are created or deleted, the Firewall is automatically updated.

## Getting Started
You’ll need an LKE cluster to run against. An LKE cluster can be deployed via the Linode Cloud Manager[cloud.linode.com], APIv4[developers.linode.com], or the Linode CLI[https://www.linode.com/docs/products/tools/cli/get-started/]

### Running on the cluster
1. Install the ClusterwideNetworkPolicy Custom Resource Definition and linode-firewall-controller:

```sh
kubectl apply -k config/crd
kubectl apply -k config/manager
kubectl apply -k config/rbac
```
2. Deploy a ClusterwideNetworkPolicy resource
Create a new ClusterwideNetworkPolicy, or use the provided sample manifest to get started:
```sh
kubectl apply -f config/samples
```

Example ClusterwideNetworkPolicy:
```yaml
apiVersion: networking.linode.com/v1alpha1
kind: ClusterwideNetworkPolicy
metadata:
  labels:
  name: clusterwidenetworkpolicy-base
spec:
# The list of rules defined in this example are required to support normal LKE cluster functionality
  ingress:
  # allow web traffic from 172.0.0.0/12
  - from:
    - cidr: 192.168.128.0/17
    ports:
    # Kubelet health checks
    - protocol: TCP
      port: 10250
    # Calico BGP
    - protocol: TCP
      port: 179
    # wireguard tunneling for for kubectl proxy
    - protocol: UDP
      port: 51820
  - from:
    ports:
    # allow NodePorts services
    - protocol: TCP
      port: 30000
      endPort: 32767
    - protocol: UDP
      port: 30000
      endPort: 32767
```

### Developing
1. Install the CRDs into the cluster:

```sh
make install
```

2. Run your controller (this will run in the foreground, so switch to a new terminal if you want to leave it running):

```sh
make run
```

Or via Kubernetes Manifests:
1. Build and push your image to the location specified by `IMG`:
	
```sh
make docker-build docker-push IMG=<some-registry>/linode-firewall-controller:tag
```
	
2. Deploy the controller to the cluster with the image specified by `IMG`:

```sh
make deploy IMG=<some-registry>/linode-firewall-controller:tag
```

### Uninstall CRDs
To delete the CRDs from the cluster:

```sh
make uninstall
```

### Undeploy controller
UnDeploy the controller to the cluster:

```sh
make undeploy
```

### Modifying the API definitions
If you are editing the API definitions, generate the manifests such as CRs or CRDs using:

```sh
make manifests
```

**NOTE:** Run `make --help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## License

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

