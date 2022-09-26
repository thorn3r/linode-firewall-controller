# linode-firewall-controller
The linode-firewall-controller extends support for Linode Cloud Firewalls to LKE.
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
kubectl apply -k config/sample
```

Example ClusterwideNetworkPolicy:
```yaml
apiVersion: networking.linode.com/v1alpha1
kind: ClusterwideNetworkPolicy
metadata:
  labels:
    app.kubernetes.io/name: clusterwidenetworkpolicy
    app.kubernetes.io/instance: clusterwidenetworkpolicy-sample
    app.kubernetes.io/part-of: linode-firewall-controller
    app.kuberentes.io/managed-by: kustomize
    app.kubernetes.io/created-by: linode-firewall-controller
  name: clusterwidenetworkpolicy-sample
spec:
  ingress:
  # allow web traffic from 172.0.0.0/12
  - from:
    - cidr: 172.0.0.0/12
    ports:
    - protocol: TCP
      port: 80
  egress:
  # allow egress DNS to all private network addresses
  - to:
    - cidr: 192.168.128.0/17
    ports:
    - protocol: UDP
      port: 53
```

### Developing
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

## Contributing
// TODO(user): Add detailed information on how you would like others to contribute to this project

### How it works
This project aims to follow the Kubernetes [Operator pattern](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/)

It uses [Controllers](https://kubernetes.io/docs/concepts/architecture/controller/) 
which provides a reconcile function responsible for synchronizing resources untile the desired state is reached on the cluster 

### Test It Out
1. Install the CRDs into the cluster:

```sh
make install
```

2. Run your controller (this will run in the foreground, so switch to a new terminal if you want to leave it running):

```sh
make run
```

**NOTE:** You can also run this in one step by running: `make install run`

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

