# Manual Setup of Kubernetes Services using IPtables

TThis is a series of discussions that builds off [Dola's article on Kubernetes networking and iptables](https://guide.aws.dev/articles/AR2fdoT2ZkSlGyX9JMVwNfeQ#midway). We take a look at a hands-on implementation of a custom cluster networking, to fully understand how Kubernetes sets up its own;

- iptables configuration for pod-to-pod, and pod-to-external-endpoint connections, 
- ipvs and nftable implementation, replacing iptables - to reduce the number of iptables rules required, which could grow very large, 
- and round off with troubleshooting suggestion for aws-node(CNI) liveness/readiness probe errors, and component failures connecting to `kubernetes.svc` API endpoint within cluster.

### Implementation

This hands-on tutorial starts by building 2 pod network sandboxes manually, and pointing out what part of this process would be implemented by Kubelet, CRI, CNI and kube-proxy. It is recommended to try this on an cluster worker-node with some pods running, to be able to contrast the manual pods with some Kubernetes pod under k8s.io contaunerd namespace, and also to take advantage of some system network configuration, but not a requirement.

Some simplification we introduce in creating a pod eliminates certain Kubernetes complexities during pod creation, like;

- kubelet creating a podA.slice CPU cgroup under /run/systemd/system/kubepods.slice hierarchy, instead we use the default user slice for the manual pods
- Container runtime interface (CRI) creating a sandbox for pod under /var/lib/containerd/io.containerd.runtime.v2.task/default/, instead we use the "default" containerd pod namespace
- we however, do the container network interface (CNI) tasks of creating a network namespace (net-ns), managing IP, and wiring up the network, similarly to how they are done on Kubernetes clusters. This is a very CNI-dependent process, but the networking expectations remain the same.
- then we run a container task in these network namespaces. So let's dive right in shall we.

#### Configure The Networking

Let's start with a few handy commands to take a look at the current network namespaces(net-ns) on the computer/worker-node, and the network interfaces. We will run these commands often as we progress to see the changes configured. It is possible to already have net namespaces(net-ns) built by a cluster CNI, e.g, cni-ABCDEFG on a worker node.

```sh
sudo ip netns
sudo ip link show
```

1. We create two new network namespaces(net-ns) of our own for the pods, `pod-1` and `pod-2`, that we will create manually. We will call these namespaces `veth-ns-test-pod-1` and `veth-ns-test-pod-2`. Nomenclature is to indicate we are using kernel virtual ethernet devices. Run the handy check commands above after this configuration to see the changes in current net-ns again.

```sh
sudo ip netns add veth-ns-test-pod-1
sudo ip netns add veth-ns-test-pod-2
```

2. Next, we create the Linux virtual ethernet network devices used for by the pod sandbox, and at the same time, the peer for these veth interfaces.

|    a. run the handy checks to view the current devices on the compute after the configuration below

```sh
sudo ip link add veth-pod-1 type veth peer name veth-peer-pod-1
sudo ip link add veth-pod-2 type veth peer name veth-peer-pod-2
```

3. In no particular order, we need to move the `veth-pod-1` and `veth-pod-2` devices into the network namespaces, `veth-ns-test-pod-1` and `veth-ns-test-pod-2`, respectively. This could have been done with step 2 above, but for clarity, we do this separately.

|    a. again run the handy check after the configuration below, and `veth-pod-1@veth-peer-pod-1` and `veth-pod-2@veth-peer-pod-2` interfaces should no longer be listed in the host's network, while the peers are. The veth interfaces have been moved into distinct net-ns.

```sh
sudo ip link set dev veth-pod-1 netns veth-ns-test-pod-1
sudo ip link set dev veth-pod-2 netns veth-ns-test-pod-2
```

|    b. To see the veth devices in their respective namespaces, run;

```sh
sudo ip netns exec veth-ns-test-pod-1 ip link show
sudo ip netns exec veth-ns-test-pod-2 ip link show
```

4. Notice in the command above that the Loopback interface in the network namespaces are currently DOWN. We need to turn this `UP` or basic 127.0.0.1 network connections; e.g self-health check on localhost:8080/healthz would fail for the processes(pods) in these network namespaces

```sh
sudo ip netns exec veth-ns-test-pod-1 ip link set dev lo up
sudo ip netns exec veth-ns-test-pod-2 ip link set dev lo up
```

5. Also, notice that the veth interfaces in the custom namespaces, and the peers in the host network namespace are also DOWN, lets set all these up;

```sh
sudo ip link set dev veth-peer-pod-1 up
sudo ip link set dev veth-peer-pod-2 up

sudo ip netns exec veth-ns-test-pod-1 ip link set dev veth-pod-1 up
sudo ip netns exec veth-ns-test-pod-2 ip link set dev veth-pod-2 up
```

----

#### Create Manual Pods 1 & 2

At this point, we can a rough pod networking setup and can rollout test containers into pod sandboxes using these net-ns and poke around inside the pod. This should reveal the current networking limitations, as the work of the CNI is mostly done, but we haven't wired up the network yet, no IP assigned to pod, no routes for pod-to-pod or external endpoints, etc., we can then fix these limitations.

6. We create two container/task sandboxes (pods) in a similar directory where containerd(CRI) creates Kubernetes pods sandboxes. You should look around this directory if desired to see running pods, if you have them.

```sh
sudo mkdir -p /run/containerd/pod-1/
sudo mkdir -p /run/containerd/pod-2/
```

|   a. we are going to pull a trusted nginx container image as the base image for all our containers, and create a container spec -  a container config.json specifies how runc initialized a container. This is similar to kubelet invoking the CRI, which pulls and validates the pod container images.

```sh
sudo ctr image pull docker.io/nginxinc/nginx-unprivileged:latest && \
sudo ctr run --detach docker.io/nginxinc/nginx-unprivileged:latest default-nginx

sudo cp -r /run/containerd/io.containerd.runtime.v2.task/default/default-nginx/rootfs /run/containerd/pod-1/
sudo cp -r /run/containerd/io.containerd.runtime.v2.task/default/default-nginx/rootfs /run/containerd/pod-2/

cd /run/containerd/pod-2/ && sudo runc spec 
cd /run/containerd/pod-1/ && sudo runc spec
```

NB: you can always check on what config has changed in the container spec at any point, by making a backup now for later comparisons

```sh
sudo cp config.json config.json.bkp
sudo diff -y config.json.bkp config.json
```

|   b. update the container spec with the manually created network namespaces for both pod-1 and pod-2, and and start the container using runc. This is exactly how containerd starts containers for kubelet as well. Created network namespaces are located in `/var/run/netns`

```sh
echo $(jq '(.linux.namespaces[] | select(.type == "network")) += \
{"path": "/var/run/netns/veth-ns-test-pod-1"}' /run/containerd/pod-1/config.json)  \
| sudo tee -i /run/containerd/pod-1/config.json

echo $(jq '(.linux.namespaces[] | select(.type == "network")) += \
{"path": "/var/run/netns/veth-ns-test-pod-2"}' /run/containerd/pod-2/config.json) \
| sudo tee -i /run/containerd/pod-2/config.json
```

|   c. let us also set the default nginx startup instructions to ensure the servers start, this is the pod manifest `.spec.containers[].command` in kubernetes. Also, allow container root access (not strictly required for the nginx image used), and add some Linux CAPs, these are necessary for nginx servers to start up with required network capabilities;

```sh
sudo echo $(jq '.process.capabilities.bounding += [ "CAP_CHOWN", "CAP_SETGID", "CAP_SETUID" ] \
| .process.capabilities.permitted += [ "CAP_CHOWN", "CAP_SETGID", "CAP_SETUID" ] \
| .root.readonly = false | .process.args = [ "/docker-entrypoint.sh", "nginx", "-g", "daemon off;" ]' /run/containerd/pod-1/config.json)  \
| sudo jq '.' | sudo tee -i /run/containerd/pod-1/config.json

sudo echo $(jq '.process.capabilities.bounding += [ "CAP_CHOWN", "CAP_SETGID", "CAP_SETUID" ] \
| .process.capabilities.permitted += [ "CAP_CHOWN", "CAP_SETGID", "CAP_SETUID" ] \
| .root.readonly = false | .process.args = [ "/docker-entrypoint.sh", "nginx", "-g", "daemon off;" ]' /run/containerd/pod-2/config.json) \
| sudo jq '.' | sudo tee -i /run/containerd/pod-2/config.json
```

|   d. Next, we now run the containers. The way we invoke [runc without providing file descriptors](https://github.com/opencontainers/runc/blob/main/docs/terminals.md), we need to start different shell sessions for each container.

```sh
cd /run/containerd/pod-1/ && sudo runc run pod-1
cd /run/containerd/pod-2/ && sudo runc run pod-1
sudo runc list
```

!!! info "Runc Terminal Handling"

    In order to keep this discussion streamlined, we are going to let runc reparent the container process to the calling shells  - in other words, our current terminal will be captured as stdout and stderr for the containers. The popular kubernetes CRI, containerd, CRI-O, etc. manages container runtime by implementing a wrapper around runc and providing a socket file descriptor that runc sets the container up with - this is what powers functionality such as `kubectl logs` and `kubectl exec -it`

|   a. To poke arround the pod environment - check the /proc/net directory of the container task, and do the same for pod-2- retrieve the pid of the container that is started - the PID can be used to enter the process' namespaces, with `nsenter -n -t <PID>` command, as runc has exited and parented the current shell to the container, there is no other way to exec back into this running (*pod)container. For the simplicity of our conversation we will use the `ip netns` to exec into the process namespace without needing to look up PIDs going forward

```sh
sudo runc list
sudo nsenter -n -t <PID> curl localhost:8080
sudo nsenter -n -t <PID> curl amazon.com
sudo nsenter -n -t <PID> cat /proc/net/route
```

The `localhost` connection succeeds from the command above, while the connection to an external `amazon.com` endpoint fails with `Could not resolve host amazon.com` - as there are no routes set up. So, lets us finish wiring up the pod networking, as a CNI would.


#### Wiring Up The Pod Network

7. we continue the setup by assigning IPs to both pod-1 and pod-2, from arbitrary private CIDR, 100.64.0.0/16, with minimal chance of collisions with any network. This is the functionality of an IPAM in cluster network. Note that we are using a virtual pod IP range, other CNIs, for example, aws-node CNI, uses real IP from the VPC subnets for a more resource-expensive but faster and better external networking.

```sh
sudo ip netns exec veth-ns-test-pod-1 ip addr add 100.64.0.9/24 dev veth-pod-1
sudo ip netns exec veth-ns-test-pod-2 ip addr add 100.64.0.10/24 dev veth-pod-2
```

8. we create the pod-to-pod connectivity next using a bridge device. Docker uses a similar bridge device for container connections, different CNIs implement this differently;

- aws CNI uses a dummy interface for pod-to-pod routing, real VPC IPs are used, so in-VPC and external networking routes setup is not required
- calico/weave uses a tunnel device for pod-to-pod connection, virtual IPs are used, which can be IP resource cheap but expensive routing and connecting to external endpoints

|   a. bring up a bridge device for the in-cluster connections

```sh
sudo ip link add custom-cni type bridge 
```

|   b. most CNIs use the default gateway address of 169.254.1.1 in pod namespaces. However, for clarity we use the 100.64.0.1 of the pod virtual IP CIDR range

```sh
sudo ip addr add 100.64.0.1/24 dev custom-cni
sudo ip link set custom-cni up
```

|   c. plug the veth peer devices of the pods currently in the host network namespace into the custom-cni bridge device - check the routes in pod net-ns (`cat /proc/net/route` or `ip route`) and notice the net manager has configured the routes wired up, also notice veth-peer in host net-ns has been set to be promiscuous (`ip -details link show veth-peer-pod-1`)

```sh
sudo ip link set dev veth-peer-pod-1 master custom-cni
sudo ip link set dev veth-peer-pod-2 master custom-cni
```

|    d. lets add a default route to send traffic through the bridge, 

```sh
sudo ip netns exec veth-ns-test-pod-1 ip route add default via 100.64.0.1
sudo ip netns exec veth-ns-test-pod-2 ip route add default via 100.64.0.1
```

|   e. if both containers not already started in step 7e., run pod-1 and pod-2 in 2 separate terminals - `cd /run/containerd/pod-2/ && sudo runc run pod-2`. Open a 3rd terminal and we can test connectivity from one pod to the second pod, and itself

```sh
sudo ip netns exec veth-ns-test-pod-1 curl -ikv 100.64.0.9:8080
sudo ip netns exec veth-ns-test-pod-1 curl -ikv 100.64.0.10:8080
sudo ip netns exec veth-ns-test-pod-1 curl -ikv amazon.com
```

*`Troubleshooting tip`*: You can always diagnose pod network status and issues by running a tcpdump on interfaces in the pod network namespaces, while making inbound or outbound connections from yet another terminal, then analyze packet capture with;

```sh
sudo ip netns exec veth-ns-test-pod-1 tcpdump -vvv -i any -w pod1.pcap
sudo tcpdump -r pod1.pcap
```

The pod network connection to itself and connection from pod-1 to pod-2 and vice-versa, using assigned IPs succeed, but external connection to `amazon.com` continues to fail. Depending on familiarity with iptables, [Dola's article](https://guide.aws.dev/articles/AR2fdoT2ZkSlGyX9JMVwNfeQ#midway) may be appropriate requisite reading, but we will highlight iptables usage here enough for our discussion as well.

Why does pod-to-pod connections succeed after setting up the bridge? Well, in a pod-to-pod connection on the same host, packets are flowing from one Linux process to another, and not using any external network interfaces. The bridge we created loads with netfilter_call mode enabled by default, and from the perspective of the iptable traversal, packet flow would look like;

![Pod-1-to-Pod-2](https://raw.githubusercontent.com/AbeOwlu/kube-journal/refs/heads/docs/docs/assets/ip5.drawio.png?token=GHSAT0AAAAAACR2TFHYGYTRZWVC42BJ5DNEZ2BDWTQ)

!!! warning "NB: Troubleshooting Issues"
    if you have unexpected connection issues at this point. You may not be using a cluster workernode, which would have some necessary network configurations pre-implemented. See glossary section on loading bridge with net.bridge.bridge-nf-call-iptables on non-cluster computers. And check the troubleshooting tips in the article to get grease under your finger nails. 

- the raw iptables chains aren't often used by most processes for good reason, and are usually pass through by default. An example reason, a process' packet that should be monitored by conntrack should not match rules in the raw-OUTPUT. This table is invoked before conntrack netfilter hooks are called by the kernel. While the other chains allow the packet to flow;

- `sudo iptables -L FORWARD -t mangle`- mangle-FORWARD is ACCEPT by default and open
- `sudo iptables -L FORWARD -t filter` - filter-FORWARD is ACCEPT by default for packet not matching rules in the chain. 

---

We can make a quick test to block packets from pod-1(100.64.0.9/32) specifically, while pod-2 is still allowed

```sh
sudo iptables -A FORWARD -t filter -s 100.64.0.9/32 -j DROP
sudo ip netns exec veth-ns-test-pod-1  curl -ikv 100.64.0.10:8080
```

- allow connection from pod-1 again by removing this firewall rule;

```sh
sudo iptables -D FORWARD -s 100.64.0.9/32 -j DROP
```

NB: nodeLocalDNS is an example of a kubernetes component that does use raw-OUTPUT, which would cause its traffic not to appear in the conntrack table.

---

Next, we complete setting up our custom network paths, as pictured below, on the compute node. At any point, you can perform the actions in `Troubleshooting tip` above and analyze captured packets to see its flow;

![image](https://raw.githubusercontent.com/AbeOwlu/kube-journal/refs/heads/docs/docs/assets/ip4.drawio.png?token=GHSAT0AAAAAACR2TFHY7CLTHC3ROZDJCYXEZ2BDYFQ)

The last CNI task we perform is set up pod-to-external destination network routes. Then we perform the kube-proxy component's function by creating custom virtual services to expose our custom pods, pod-1 and pod-2 containers, simulating Kubernetes clusterIP service, to round off this discussion.

9. we set up iptables rule to allow communication from our cluster custom-cni bridge interface on a network range of 100.64.0.0/16 to connect externally through the current VPC, and whatever network range it has. From the perspective of iptable traversal, packet flow would look like;

![pod-to-external](https://raw.githubusercontent.com/AbeOwlu/kube-journal/refs/heads/docs/docs/assets/ip1.drawio.png?token=GHSAT0AAAAAACR2TFHYJG4YHOVQTM3VDNUOZ2BDY5A)

- the switch from our custom-cni bridge interface to the node's primary interface in ROUTING DECISIONS is performed by the kernel netwrok module
- `sudo iptables -L OUTPUT -t mangle && sudo iptables -L POSTROUTING -t mangle` are open chains allowing free packet flow by default, as are the others
- the packets from the pods are egressing into the VPC using the private virtual IPs we assigned - 100.64.0.9 and 100.64.0.10. Amazon VPC, and most network will reject/drop this packet with unknown source IP address by default for (AWS) security reasons. We need to SNAT pod traffic to external destinations similar to aws CNI AWS-SNAT-CHAIN rules. There are a number of ways to achieve this SNAT, with simplicity as our main consideration - we will implement it in the last chain above, nat-POSTROUTING;

|   a. retrieve the primary private IP of your worker node

```sh
nodeIP=$(sudo ip -details -j addr show | jq '.[].addr_info[] | select(.label == "eth0") | .local') && localIP=$(sudo echo ${nodeIP} | tr -d '"')
```

|   b. we insert a rule in the nat-POSTROUTING chain, matching packet from the pod CIDR, and tracking connections to external destination, i.e. not local, and SNAT the packet - change source IP address from the pod IP to the host IP. 

```sh
sudo iptables -I POSTROUTING -t nat -s 100.64.0.0/16 -m addrtype ! --dst-type LOCAL -m conntrack --ctstate NEW,ESTABLISHED -j SNAT --to-source ${localIP}
```
Test: `sudo ip netns exec veth-ns-test-pod-1 curl -ikv amazon.com`

10. Lastly, we use iptables to expose the pod-1, 100.64.0.9 and pod-2, 100.64.0.10, behind virtual service IPs which we will pick from an arbitraru range of 198.19.0.0/16, with minimal collision chance. We will stick close to how kube-proxy sets up a similar clusterIP service type. First, the iptable traversal from pod-1 to service-2 delivered to pod-2 looks like this;

![cluster-IP-flow](https://raw.githubusercontent.com/AbeOwlu/kube-journal/refs/heads/docs/docs/assets/ip2.drawio.png?token=GHSAT0AAAAAACR2TFHY7UMUQJPVXJDVXFN4Z2BDZYQ)

|   a. create a custom network service chains, CUSTOM-CLUSTER-SERVICES, CUSTOM-SERVICES-1 and CUSTOM-SERVICES-2 in the nat table, synonymous to the KUBE-SERVICES chain created by kube-proxy which is used for clear rules management. Then, create the required service endpoint (SEP) chain for service-to-pod routing, also in the nat table;

```sh
sudo iptables -t nat -N CUSTOM-CLUSTER-SERVICES
sudo iptables -t nat -N CUSTOM-SERVICES-1
sudo iptables -t nat -N CUSTOM-SERVICES-2
sudo iptables -t nat -N CUSTOM-SEP-1
sudo iptables -t nat -N CUSTOM-SEP-2
```

|   b. importantly, we inform the main iptables nat-PREROUTING and nat-OUTPUT chains to look through our nat-CUSTOM-CLUSTER-SERVICES chain during packet processing. If you don't add the nat-OUTPUT rule here, connection from the host to service IP 198.19.0.9:8080 fails, but pod-x-to-service-y succeeds, try to understand what happened to the node's packets to the pod, use the troubleshooting tip and iptables flow diagram above.

```sh
sudo iptables -I PREROUTING -t nat -m comment --comment "custom-cluster-services" -j CUSTOM-CLUSTER-SERVICES
sudo iptables -I OUTPUT -t nat -m comment --comment "custom-cluster-services" -j CUSTOM-CLUSTER-SERVICES
```

|   c. next, we configure CUSTOM-CLUSTER-SERVICES to look through CUSTOM-SERVICES-1 and CUSTOM-SERVICES-2 chains, we can restrict the network protocols, e.g., tcp(6), udp(17), etc., that the service endpoint accepts in this chain, like kube-proxy, or in any of the later chains. But we leave it open to all protocols for simplicity.

```sh
sudo iptables -A CUSTOM-CLUSTER-SERVICES -t nat -d 198.19.0.9 -m comment --comment "Rule to service-1 -> 198.19.0.9" -j CUSTOM-SERVICES-1
sudo iptables -A CUSTOM-CLUSTER-SERVICES -t nat -d 198.19.0.10 -m comment --comment "Rule to service-2 -> 198.19.0.10" -j CUSTOM-SERVICES-2
```

|   d. configure the iptables rule in CUSTOM-SERVICES-1 and CUSTOM-SERVICES-2 to look through the service endpoint (SEP) chains, CUSTOM-SEP-1 and CUSTOM-SEP-2, this is another rule that could be eliminated from the stack, but kube-proxy uses it for readability and rule management, and we are sticking with kube-proxy implementation, so;

```sh
sudo iptables -A CUSTOM-SERVICES-1 -t nat -m comment --comment "Rule to service-1-endpoionts" -j CUSTOM-SEP-1  
sudo iptables -A CUSTOM-SERVICES-2 -t nat -m comment --comment "Rule to service-2-endpoionts" -j CUSTOM-SEP-2 
```

|   e. for the virtual service IP functionality - sending all traffic received at service IP to endpoint pod IP - configure the following rules in the CUSTOM-SEP-X chains for `198.19.0.9 to 100.64.0.9` and `198.19.0.10 to 100.64.0.10`

```sh
sudo iptables -A CUSTOM-SEP-1 -t nat -p tcp -j DNAT --to-destination 100.64.0.9:8080
sudo iptables -A CUSTOM-SEP-2 -t nat -p tcp -j DNAT --to-destination 100.64.0.10:8080
```

|   f. test connectivity in all directions, from the node to the service IPs, from pod-1 to service-2 IP, from pod-1 to service-1 IP

```sh
curl -ikv 198.19.0.9:8080
curl -ikv 198.19.0.10:8080
sudo ip netns exec veth-ns-test-pod-1 curl 198.19.0.10:8080
...
```

One last, thing for the sake of completeness. Note that pod-1 and pod-2 are unable to connect to itself using the service IP exposing them. Test connection from a pod-1 through service-1 IP exposing it, and for pod-2;

```sh
sudo ip netns exec veth-ns-test-pod-2  curl -ikv 198.19.0.10:8080
```

*`Troubleshooting tip`*: You can check the troubleshooting article in this series of discussion for in-depth look. To understand what is occurring to our packets, here, however, let us check the flow, open 3 new terminals

```sh
terminal 1: `sudo tcpdump -vvv -n host 198.19.0.10 -i custom-cni`
terminal 2: `sudo ip netns exec veth-ns-test-pod-2 tcpdump -vvv -n host 198.19.0.10 -i any`
terminal 3: `sudo ip netns exec veth-ns-test-pod-2 curl -ikv 198.19.0.10:8080`
```

In terminal 1, note that pod-2 is sending SYN packets to the `198.19.0.10.webcache` endpoint, that are never ACK'd. In terminal 2, the custom-cni bridge is discarding the packet that should be sent from `198.19.0.10` back to the originating pod-2. This issue is occurring because the bridge does not allow hairpin traffic by default. To correct this, check the current bridge interface configuration and enable promiscuous mode with;

```sh
sudo ip -details link show custom-cni
sudo ip link set custom-cni promisc on
```

At this point, we have manually created 2 pods running nginx containers and set up a full pod networking on a compute/worker node. Implementing the specification of the OCI CNI requirements](https://github.com/containernetworking/cni) manually, to better understand how cluster networks. To top it off, we have exposed these pods behind our own service IPs within the cluster. In the next discussion, we expose these pods publicly, and look into the benefits of using the newer IPVS mode of kube-proxy over iptables rules management.

Finally, if desired, you can clean up all the implementation above;
```
##Stopping the containers
sudo runc kill pod-1 KILL 

## Deleting the chains
sudo iptables -t nat -D <$CHAIN_NAME>
```

#### Glossary
##### Non-EKS EC2 Compute AMIs
- Check that the following system network configurations are the indicated values. If not, update the sys config to these values on non-EKS provided AMI

```sh
`sudo sysctl net.ipv4.ip_forward` : 1
`sudo sysctl net.bridge.bridge-nf-call-iptables` : 1
`sudo systctl net.ipv4.conf.all.rp_filter` : 1
```

- [Linux Networking reference](https://commons.wikimedia.org/wiki/File:Netfilter-packet-flow.svg)