# Manual Setup of Kubernetes Services using IPVS

In the [first discussion in this series](article8-netwrking.md), we created a custom cni networking for 2 pod containers, and exposed them behind 2 virtual services (clusterIP). That discussion is requisite to this one - where we look into the benefits of IPVS mode over iptables mode in cluster orchestration, and replace our iptables rules implementation with IPVS rule sets in the custom container network.

### Implementation

We will start by adding 2 more pods to our custom network, with each pod added as a second endpoint behind the existing custom services, service-1 and service-2. Then we expose these services externally on a nodePort, to understand how kube-proxy sets this up for kubernetes clusters. And optionally expose the nodePorts behind an elastic loadbalancer for public connections. This should hopefully give us deep insight into our iptables rule management grows for each additional service and pod(s). Then we replace our iptables configuration with IPVS to use the benefits of the latter that we discuss, for kernel packet distribution.

#### Create Pod 3 & 4 Sandboxes

1. we add 2 more pod sandboxes, pod-3 and pod-4 to our cluster, by running a few of the steps in the first discussion.

|   a. networking configuration commands;

```sh
sudo ip netns add veth-ns-test-pod-3
sudo ip netns add veth-ns-test-pod-4

sudo ip link add veth-pod-3 type veth peer name veth-peer-pod-3
sudo ip link add veth-pod-4 type veth peer name veth-peer-pod-4

sudo ip link set dev veth-pod-3 netns veth-ns-test-pod-3
sudo ip link set dev veth-pod-4 netns veth-ns-test-pod-4

sudo ip netns exec veth-ns-test-pod-3 ip addr add 100.64.0.19/24 dev veth-pod-3
sudo ip netns exec veth-ns-test-pod-4 ip addr add 100.64.0.20/24 dev veth-pod-4

sudo ip link set dev veth-peer-pod-3 master custom-cni
sudo ip link set dev veth-peer-pod-4 master custom-cni

sudo ip netns exec veth-ns-test-pod-3 ip link set dev lo up
sudo ip netns exec veth-ns-test-pod-4 ip link set dev lo up

sudo ip link set dev veth-peer-pod-3 up
sudo ip link set dev veth-peer-pod-4 up

sudo ip netns exec veth-ns-test-pod-3 ip link set dev veth-pod-3 up
sudo ip netns exec veth-ns-test-pod-4 ip link set dev veth-pod-4 up

sudo ip netns exec veth-ns-test-pod-3 ip route add default via 100.64.0.1
sudo ip netns exec veth-ns-test-pod-4 ip route add default via 100.64.0.1
```

|    b. create pod-3 and pod-4 containers, and we misuse our root privileges on a cluster worker node to edit container filesystem, displaying a page that indicates the pod IP behind the fronting service, 1 or 2, that receives our connections traffic when we access the nginx server. If it is not immediately apparent why this is a security issue, then it is likely for the best. However, this shows why it is a security concern that pod applications in multi-tenant, no-trust clusters, or any cluster at all, never break out unto the node.

```sh
sudo mkdir -p /run/containerd/pod-3/
sudo mkdir -p /run/containerd/pod-4/

pod1=$(sudo sudo ip netns exec veth-ns-test-pod-1 ip -details -j addr show | jq '.[].addr_info[] | select(.label == "veth-pod-1") | .local')
pod3=$(sudo sudo ip netns exec veth-ns-test-pod-3 ip -details -j addr show | jq '.[].addr_info[] | select(.label == "veth-pod-3") | .local')
sudo sed -i "s/<p>If/<p>Pod-1 Endpoint From Service-1 Pod-IP: $pod1 \n\n\nIf/1" /run/containerd/pod-1/rootfs/usr/share/nginx/html/index.html
sudo cp -r /run/containerd/pod-1/rootfs /run/containerd/pod-3
sudo sed -i "s/Pod-1/Pod-3/;s/$pod1/$pod3/g" /run/containerd/pod-3/rootfs/usr/share/nginx/html/index.html

pod2=$(sudo sudo ip netns exec veth-ns-test-pod-2 ip -details -j addr show | jq '.[].addr_info[] | select(.label == "veth-pod-2") | .local')
pod4=$(sudo sudo ip netns exec veth-ns-test-pod-4 ip -details -j addr show | jq '.[].addr_info[] | select(.label == "veth-pod-4") | .local')
sudo sed -i "s/<p>If/<p>Pod-2 Endpoint From Service-2 Pod-IP: $pod2 \n\n\nIf/1" /run/containerd/pod-2/rootfs/usr/share/nginx/html/index.html
sudo cp -r /run/containerd/pod-2/rootfs /run/containerd/pod-4
sudo sed -i "s/Pod-2/Pod-4/;s/$pod2/$pod4/g" /run/containerd/pod-4/rootfs/usr/share/nginx/html/index.html

cd /run/containerd/pod-3/ && sudo runc spec 
cd /run/containerd/pod-4/ && sudo runc spec

echo $(jq '(.linux.namespaces[] | select(.type == "network")) += {"path": "/var/run/netns/veth-ns-test-pod-3"}' /run/containerd/pod-3/config.json)  | sudo tee -i /run/containerd/pod-3/config.json
echo $(jq '(.linux.namespaces[] | select(.type == "network")) += {"path": "/var/run/netns/veth-ns-test-pod-4"}' /run/containerd/pod-4/config.json)  | sudo tee -i /run/containerd/pod-4/config.json

sudo echo $(jq '.process.capabilities.bounding += [ "CAP_CHOWN", "CAP_SETGID", "CAP_SETUID" ] \
| .process.capabilities.permitted += [ "CAP_CHOWN", "CAP_SETGID", "CAP_SETUID" ] \
| .root.readonly = false | .process.args = [ "/docker-entrypoint.sh", "nginx", "-g", "daemon off;" ]' /run/containerd/pod-3/config.json)  \
| sudo jq '.' | sudo tee -i /run/containerd/pod-3/config.json

sudo echo $(jq '.process.capabilities.bounding += [ "CAP_CHOWN", "CAP_SETGID", "CAP_SETUID" ] \
| .process.capabilities.permitted += [ "CAP_CHOWN", "CAP_SETGID", "CAP_SETUID" ] \
| .root.readonly = false | .process.args = [ "/docker-entrypoint.sh", "nginx", "-g", "daemon off;" ]' /run/containerd/pod-4/config.json)  \
| sudo jq '.' | sudo tee -i /run/containerd/pod-4/config.json

cd /run/containerd/pod-3 && sudo runc run pod-3
---
#Open a new terminal and start pod-4
cd /run/containerd/pod-4 && sudo runc run pod-4
```

2. with the pods' containers running and reachable within cluster network, we are going to add pod-3 as a second endpoint behind service-1 and pod-4 as behind service-2. Kube-proxy adds endpoint by watching for new endpoint/slice on the API server. Then builds the appropriate proxy rules, and updates Iptables chains on every node.

|   a. in our manual implementation, we simply could add our new pod IPs as endpoints in CUSTOM-SEP-1 and CUSTOM-SEP-2 chains. However, for readability and adhering to how kube-proxy implements routing; we will create 2 new service endpoints SEP-3 and SEP-4, dedicated to the new pod-3 and pod-4

```sh
sudo iptables -t nat -N CUSTOM-SEP-3
sudo iptables -t nat -N CUSTOM-SEP-4

sudo iptables -A CUSTOM-SEP-3 -t nat -p tcp -j DNAT --to-destination 100.64.0.19:8080
sudo iptables -A CUSTOM-SEP-4 -t nat -p tcp -j DNAT --to-destination 100.64.0.20:8080
```

|   b. we then insert the probabilistic routing rules, pairing the odd and even number pods, such that CUSTOM-SERVICES-1 now also routes to CUSTOM-SEP-3, and CUSTOM-SERVICES-2 chains routes to CUSTOM-SEP-4.

```sh
sudo iptables -t nat -I CUSTOM-SERVICES-1 -m comment --comment "Rule to service-1-endpoionts 50% Probability" -m statistic --mode random --probability 0.5 -j CUSTOM-SEP-3
sudo iptables -t nat -I CUSTOM-SERVICES-2 -m comment --comment "Rule to service-2-endpoionts 50% Probability" -m statistic --mode random --probability 0.5 -j CUSTOM-SEP-4
```

|   c. we test the random distribution of traffic by connecting to service-1 or 2, ten times and checking how many are routed to either backend pods behind the service we connect to. Iptables load balancing works using a random probabilistic distribution to choose which endpoint is sent a connection.

```sh
for i in {1..10}; do curl -ikvs 198.19.0.10:8080/ 2>/dev/null; done | grep "Pod-4" | wc -l
for i in {1..10}; do curl -ikvs 198.19.0.9:8080/ 2>/dev/null; done | grep "Pod-3" | wc -l
```

Traffic from external sources, node, ELB, etc. to a pod on a node would traverse the iptables chains below;
![External-to-Node-Pod](/media/postImages/original/IMswHejOOrTuOYf9TBLzhl0g)


#### Expose Node Port (Optional: Configure ELB Access)

Connecting to service-1 on `198.19.0.9:8080`, in the test above, for example, the endpoints that get the traffic is completely random, and you will get different response distribution from pod-1 and pod-3 each time. To perhaps make this a bit more visual, and build on our understanding of kube-proxy cluster networking, we will create an iptables rule simulating a kubernetes nodePort service type and optionally expose it behind an Elastic Loadbalancer that we can connect to from a web browser and see what pods are responding.

3. we are going to choose arbitrary static node ports with minimal chance of conflicts with any other process on the computer, as well as Kubernetes' kube-proxy default port range: 30000-32767. For this configuration, nodePort-1 exposing pod-1 and pod-3 will be on port 65509, and nodePort-2 exposing pod-2 and pod-4 will be on port 65510.

|   a. again, we can create a single chain pointing to the CUSTOM-SERVICES-1 or 2 chains, but to implement this the way kube-proxy does, we are going to create a NODEPORT chain pointing to an EXT chain for external connection, which then points to the CUSTOM-SERVICE chains, which points to the SEP service endpoint destinations. For the traffic we intend to expose externally, we enforce tcp (6) traffic protocol in these flows for security.

```sh
sudo iptables -t nat -N CUSTOM-NODEPORTS
sudo iptables -t nat -N CUSTOM-EXT-SERVICE-1
sudo iptables -t nat -N CUSTOM-EXT-SERVICE-2

sudo iptables -t nat -A CUSTOM-CLUSTER-SERVICES -m comment --comment "NodePort rules appended in CLUSTER-SERVICES chain" -j CUSTOM-NODEPORTS
sudo iptables -t nat -A CUSTOM-NODEPORTS -m comment --comment "Nodepoort to service-1 pods" -p tcp --dport 65509 -j CUSTOM-EXT-SERVICE-1
sudo iptables -t nat -A CUSTOM-NODEPORTS -m comment --comment "Nodepoort to service-2 pods" -p tcp --dport 65510 -j CUSTOM-EXT-SERVICE-2

sudo iptables -t nat -A CUSTOM-EXT-SERVICE-1 -j CUSTOM-SERVICES-1
sudo iptables -t nat -A CUSTOM-EXT-SERVICE-2 -j CUSTOM-SERVICES-2
```

If you like, you can add a few more pods, and check the Iptables chains again, `iptables -t nat -L`. We can see how on a cluster with a few hundred endpoints, the rules would grow rapidly, becoming harder to follow. Also worth noting that with increasing number of rules does come some computing performance hit. Each chain that has to be checked is either pushed(--jump) or replacing(--goto) a frame on the stack and popped after completion.

```sh
sudo iptables -t nat -D CUSTOM-NODEPORTS -m comment --comment "Nodepoort to service-1 pods" -p tcp --dport 65509 -j CUSTOM-EXT-SERVICE-1
sudo iptables -t nat -D CUSTOM-NODEPORTS -m comment --comment "Nodepoort to service-2 pods" -p tcp --dport 65510 -j CUSTOM-EXT-SERVICE-2
sudo iptables -A CUSTOM-SEP-1 -t nat -j DNAT --to-destination 100.64.0.9:8080
sudo iptables -A CUSTOM-SEP-2 -t nat -j DNAT --to-destination 100.64.0.10:8080
sudo iptables -A CUSTOM-SEP-3 -t nat -p tcp -j DNAT --to-destination 100.64.0.19:8080
sudo iptables -A CUSTOM-SEP-4 -t nat -p tcp -j DNAT --to-destination 100.64.0.20:8080
```

---
OPTIONAL: We can expose the nodePort-1 endpoint(s) created above behind an elastic loadbanalcer (ALB).
- choose subnets with public network gateways for the ALB to allow connecting from a web browser

```sh
loadBalancerArn=$(aws ellbv2 create-load-balancer --name custom-alb-2 \
--subnets subnet-02468af75594a6335 subnet-025434f8fe8868f14 --security-groups sg-05884928af06d5957 | jq -rc '.LoadBalancer[].LoadBalancerArn')

targetGroupArn=$(aws elbv2 create-target-group --name service1-targets --protocol HTTP --port 65509 --health-check-port traffic-port \
--vpc-id vpc-0b50ec3f3729df7a8 --ip-address-type ipv4 --target-type instance | jq -rc '.TargetGroups[].TargetGroupArn')

aws elbv2 register-targets --target-group-arn $targetGroupArn --targets Id=`${node-EC2-ID:i-00817b787137b46c7}`

listenerArn=$(aws elbv2 create-listener --load-balancer-arn $loadbalancerarn --protocol HTTP --port 80  \
--default-actions "Type=fixed-response","FixedResponseConfig={MessageBody=Retry Later,StatusCode=503,ContentType=text/plain}" | jq -rc '.Listeners.ListernerArn')

aws elbv2 create-rule --listener-arn $listenerArn --priority 1 \
--conditions "Field=path-pattern","PathPatternConfig={Values=[/,/svc1,/service1]}" --actions "Type=forward",TargetGroupArn=$targetGroupArn
```

- get the ALB DNS and paste it into a web browser, and note the non-uniform traffic distribution, even with 50% probability of hitting Pod-1 and Pod-3

```sh
aws elbv2 describe-load-balancers --name custom-alb --region us-west-2 | jq -rc '.LoadBalancers[].DNSName
```

- if you want to expose nodePort-2 behind the same ALB, update nginx config file url path served in the directory, `/run/containerd/pod-1/rootfs/etc/nginx/conf.d/default.conf` to serve location `/svc1` and `svc2` for the ALB to route to, but this is not of interest in this discussion.
---

#### Implementing IPVS

With the growing chains and rules, and non-uniform traffic distribution with Iptables apparent, IPVS aims to solve these issues by enabling accurate algorithmic load distribution, and stream-lined rules management. In future EKS AMI release, required kernel modules may be enabled by default. For now let's check then install the [required modules for IPVS](https://kubernetes.io/blog/2018/07/09/ipvs-based-in-cluster-load-balancing-deep-dive/#run-kube-proxy-in-ipvs-mode);

```sh
sudo ipvsadm

# if not present
yum install ipset ipvsadm -y
modprobe -- ip_vs
modprobe -- ip_vs_rr
modprobe -- ip_vs_wrr
modprobe -- ip_vs_sh
modprobe -- nf_conntrack
sudo sysctl --write net.ipv4.vs.conntrack=1

ipvsadm --list -n
```

IPVS acts as a more accurate loadbalancer implementation over Iptables, in Linux kernel. It creates a virtual service (these are kubernetes virtual service IP), which fronts a cluster of real servers (in kubernetes, these are the pod endpoints behind the virtual service), and algorithmically loadbalances traffic to these service endpoints. There are a number of [loadbalancing algorithms](https://kubernetes.io/blog/2018/07/09/ipvs-based-in-cluster-load-balancing-deep-dive/), available for configuration. However, for our use case, we use the round robin (ipvs_rr) algorithm. We are next going to create ipvs sets to replace our current custom iptables rules;

4. we start by creating an IPVS service endpoint from the 198.19.0.0/16 service CIDR for service-1, 198.19.10.0/32 and service-2, 192.19.20.0/32. These are going to front the endpoints, pod-1, pod-3, pod-2, and pod-4, respectively, with a round_robin distributor algorithm. It is always a good idea to check the documentation of ipvs tool, `man ipvsadm`, note the packet-forwarding-method, and that it can only distribute tcp(6) and udp(17) traffic, so will again enforce the tcp as well as udp in the rules.

|   a. create IPVS service implementation for the clusterIP service types discussed above;

```sh
sudo ipvsadm --add-service --tcp-service 198.19.10.0:8080 --scheduler rr
sudo ipvsadm --add-service --tcp-service 198.19.20.0:8080 --scheduler rr
```

|   b. add the server endpoint, i.e, the pods, that the service routes to. Masquerading packet for our packet-forwarding-method;

```sh
sudo ipvsadm --add-server --tcp-service 198.19.10.0:8080 --real-server 100.64.0.9:8080 --masquerading
sudo ipvsadm --add-server --tcp-service 198.19.10.0:8080 --real-server 100.64.0.19:8080 --masquerading

sudo ipvsadm --add-server --tcp-service 198.19.20.0:8080 --real-server 100.64.0.10:8080 --masquerading
sudo ipvsadm --add-server --tcp-service 198.19.20.0:8080 --real-server 100.64.0.20:8080 --masquerading
```

|   c. we test the traffic distribution to the service again, with the round robin algorithm, traffic is now uniformly distributed between both endpoints, using the IPVS virtual service. 5 connections should be distributed to pod-1 and pod-3 each, as well as for pod-2 and pod-4.

NB: ensure that ipv4_forward is enabled, as mentioned in the ipvsadm man page - `sudo sysctl net.ipv4.ip_forward`. If 0, see last article to enable

```sh
for i in {1..10}; do curl -ikvs 198.19.10.0:8080/ 2>/dev/null; done | grep "Pod-3" | wc -l
for i in {1..10}; do curl -ikvs 198.19.20.0:8080/ 2>/dev/null; done | grep "Pod-4" | wc -l
```

This is all the configuration required to expose the endpoints behind virtual services, and have accurate loadbalancing implemented. However, notice that we still use iptables for pod-pod, pod-host, pod-external connections. You can check connections from one pod to the IPVS virtual service IPs using a tcpdump on the pod net-ns. We can confirm there is no destination and the packet from the pod is discarded.

```sh
sudo ip netns exec veth-ns-test-pod-1 curl -ikv 198.19.20.0:8080
sudo ip netns exec veth-ns-test-pod-2 curl -ikv 198.19.10.0:8080
```

5. We are going to implement internal custom cluster network routes using IPVS next. Again, we simulate how kube-proxy would configure cluster IPVS. So we are going to create a dummy interface, custom-ipvs0 (kube-proxy sets up `kube-ipvs0`), and attach the IPVS service IPS to it. This is not dissimilar to how aws-node CNI sets up pod-to-pod networking using dummy interface, dummy0, for simply registering routable paths, as mentioned in the last article

|   a. create a dummy interface for simple destination routing to any number of attached IPs/endpoints

```sh
sudo ip link add dev custom-ipvs0 type dummy

sudo ip addr add 198.19.20.0/32 dev custom-ipvs0
sudo ip addr add 198.19.10.0/32 dev custom-ipvs0
```

|   b. we start replacing the iptables rule by creating an [ipset](https://ipset.netfilter.org/) of set type; `hash:ip,port,ip`, same as kube-proxy, that can then be referenced in nft iptables to set entire block firewall rules, instead of the current individual rule for each clusterIp, nodePort, etc. 
First, we allow loopback address from pod network namespaces to itself, for when we delete the custom-cni bridge device. Next, we configure similar rules to kube-proxy masquerading, in the nat-POSTROUTING chain for our custom IPVS chains;

```sh
sudo ipset create CUSTOM-LOOP-BACK hash:ip,port,ip
sudo ipset add CUSTOM-LOOP-BACK 100.64.0.9,tcp:8080,100.64.0.9
sudo ipset add CUSTOM-LOOP-BACK 100.64.0.10,tcp:8080,100.64.0.10
sudo ipset add CUSTOM-LOOP-BACK 100.64.0.19,tcp:8080,100.64.0.19
sudo ipset add CUSTOM-LOOP-BACK 100.64.0.20,tcp:8080,100.64.0.20

sudo iptables -I POSTROUTING -t nat -m set --match-set CUSTOM-LOOP-BACK dst,dst,src -m comment --comment "Rule matching set hash dst ip:port,source-ip for solving hairpin" -j MASQUERADE
```

|   c. we replace the iptables rules for clusterIP with ipvs sets.

```sh
sudo ipset create CUSTOM-CLUSTER-IP hash:ip,port
sudo ipset add CUSTOM-CLUSTER-IP 198.19.10.0,tcp:8080
sudo ipset add CUSTOM-CLUSTER-IP 198.19.20.0,tcp:8080

sudo iptables -A CUSTOM-CLUSTER-SERVICES -t nat -m comment --comment "***" -m set --match-set CUSTOM-CLUSTER-IP dst,dst -j ACCEPT
```

|   d. next, we create ipvs servers for nodePort service types, and map real servers to the destinations pods, then replace the iptables rules we creasted for nodePort with ipvs sets for our ipvs server.

```sh
nodeIP=$(sudo ip -details -j addr show | jq '.[].addr_info[] | select(.label == "eth0") | .local') && localIP=$(sudo echo ${nodeIP} | tr -d '"')
sudo ipvsadm --add-service --tcp-service ${localIP}:65512 --scheduler rr
sudo ipvsadm --add-service --tcp-service ${localIP}:65513 --scheduler rr

sudo ipvsadm --add-server --tcp-service ${localIP}:65512 --real-server 100.64.0.9:8080 --masquerading
sudo ipvsadm --add-server --tcp-service ${localIP}:65512 --real-server 100.64.0.19:8080 --masquerading
sudo ipvsadm --add-server --tcp-service ${localIP}:65513 --real-server 100.64.0.10:8080 --masquerading
sudo ipvsadm --add-server --tcp-service ${localIP}:65513 --real-server 100.64.0.20:8080 --masquerading

sudo ipset create CUSTOM-NODE-PORT-TCP bitmap:port range 65500-65535
sudo ipset add CUSTOM-NODE-PORT-TCP 65512
sudo ipset add CUSTOM-NODE-PORT-TCP 65513

sudo ipvsadm --add-service --tcp-service ${localIP}:65512 --scheduler rr
sudo ipvsadm --add-service --tcp-service ${localIP}:65513 --scheduler rr
sudo iptables -I CUSTOM-CLUSTER-SERVICES -t nat -m comment --comment "***" -m addrtype --dst-type LOCAL -j CUSTOM-NODEPORTS
sudo iptables -I  CUSTOM-NODEPORTS -t nat -m comment --comment "***" -m set --match-set CUSTOM-NODE-PORT-TCP dst -j ACCEPT

for i in {1..10}; do curl -ikvs ${localIP}:65512 2>/dev/null; done | grep "Pod-3" | wc -l
for i in {1..10}; do curl -ikvs ${localIP}:65513 2>/dev/null; done | grep "Pod-4" | wc -l
```

And that is all the rules required to configure clusterIP and nodePort service types using ipvs. Compared with all the configuration required for using just iptables, this implementation requires drastically fewer rules.

#### Clean-up
All the iptables rules can be deleted by providing the delete argument in all the shell commands used to configure the rule, like so;

```sh
sudo iptables -D CUSTOM-SEP-3 -t nat -p tcp -j DNAT --to-destination 100.64.0.19:8080
sudo iptables -D CUSTOM-SEP-4 -t nat -p tcp -j DNAT --to-destination 100.64.0.20:8080

sudo iptables -t nat -D CUSTOM-SERVICES-1 -m comment --comment "Rule to service-1-endpoionts 50% Probability" -m statistic --mode random --probability 0.5 -j CUSTOM-SEP-3
sudo iptables -t nat -D CUSTOM-SERVICES-2 -m comment --comment "Rule to service-2-endpoionts 50% Probability" -m statistic --mode random --probability 0.5 -j CUSTOM-SEP-4

...
```