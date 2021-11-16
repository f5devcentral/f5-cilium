:product: BIG-IP Controller for Kubernetes
:type: concept

.. _cilium-bigip-info:

Why BIG-IP and Cilium VXLAN/Geneve Integration
==============================================

Cilium CNI plugin address one main problem that the old Flannel CNI plugin missing

   * K8S Flannel CNI plugin does not support dynamic pod ARP with BIG-IP

Cilium also address the kubernetes network scale problem with revolution kernel BPF technology:

see Liberating Kubernetes From Kube-proxy and Iptables, Youtube_.

.. _Youtbube: https://youtu.be/bIRwSIwNHC0

BIG-IP and Cilium VXLAN/Geneve Integration
==========================================

This document provides a general overview of the BIG-IP device integration with Cilium VXLAN/Geneve in Kubernetes. For set-up instructions, see :ref:`use-bigip-k8s-cilium`.

Overview of Cluster Networking with Cilium in Kubernetes
---------------------------------------------------------

::

         Diagram

                         +------------+                                          
                         |            |                                          
                         |   Client   |                                          
                         +---+--------+                                          
                             |                                                   
                             |                                                   
               +--------VIP---------------+     +----------------------------+
               |                          |     |                            |
               |     BIG-IP-1             |     |  BIG-IP-2  vtepCIDR:       |
  vtepCIDR:    |                          |     |             10.1.5.0/24    |
   10.1.6.0/24 |                          |     |                            |
               |  VtepMAC  selfip         |     |selfip          VtepMAC     |
               |  VNI:2      10.169.72.34 |     | 10.169.72.36   VNI:2       |
               +-flannel_vxlan-VLAN-------+     +--VLAN-----flannel_vxlan----+
               10.1.6.34        |                    |      10.1.5.36         
                                +---+    +-----------+                    
                                    |    |                                
  podCIDR:               +----------+----+-----+     podCIDR:                      
   10.0.0.0/24           |                     |        10.0.1.0/24                
  cilium_host:           |                     |     cilium_host:                  
   10.0.0.228            |                     |        10.0.1.116                 
                         |                     |                                   
                         |                     |                                   
   +---cilium_vxlan-----ens192--+       +----ens192------cilium_vxlan-+             
   |       |      10.169.72.239 |       | 10.169.72.233         |     |             
   |       |                    |       |                       |     |             
   |    lxcxxxxx    +----------+|       |                    lxcxxxx  |             
   |       |        | cilium   ||       |+-----------+          |     |             
   |       |        | agent    ||       || cilium    |          |     |             
   |  +--eth0----+  +----------+|       || agent     |    +---eth0---+|             
   |  |          |              |       |+-----------+    |          ||             
   |  | app pod  |              |       |                 | app pod  ||             
   |  +----------+              |       |                 +----------+|             
   |              cilium node   |       |   cilium node               |             
   +----------------------------+       +-----------------------------+             


.. seealso::
   :class: sidebar


`Cilium`_ is an open source software for providing, securing and observing network connectivity between container workloads - cloud native, and fueled by the revolutionary Kernel technology eBPF. 

Cilium assigns a subnet or get pod subnet from Kubernetes for each Kubernetes Node. It allocates an IP address within that subnet to each Pod running on the Node. Because :code:`cilium` runs on every Node, all of the Pods across the Cluster can talk to each other directly.

BIG-IP Tunnel Setup for Cilium VTEP Integration
===============================================

.. note::

   BIG-IP VXLAN tunnel setup is identical to BIG-IP flannel VXLAN deployment, we even use the
   same tunnel name flannel_vxlan in CIS  ``--flannel-name="flannel_vxlan"`` so that it does not
   require any CIS code changes to make Cilium VXLAN/Geneve tunnel  work with BIG-IP VXLAN/Geneve
   tunnel. there are three differences though:

   * the tunnel profile flooding type is set to ``multipoint``

      multipoint is to make BIG-IP to send ARP broadcast request to Cilium managed nodes for pod ARP resolution.

   * the tunnel VNI key is set to ``2``

      VNI 2 is reserved identity ID in Cilium representing world traffic

   * BIG-IP requires static route setup to Cilium managed pod CIDR network

      BIG-IP tunnel subnet should not be within pod CIDR network, it may cause conflicts if a node podCIDR overlap with
      BIG-IP tunnel subnet

.. code-block:: bash

   #. Create a VXLAN tunnel profile. The tunnel profile name is fl-vxlan,
   tmsh create net tunnels vxlan fl-vxlan port 8472 flooding-type multipoint

   #. Create a VXLAN tunnel, the tunnel name is ``flannel_vxlan``
   tmsh create net tunnels tunnel flannel_vxlan key 2 profile fl-vxlan local-address 10.169.72.34

   #. Create VXLAN tunnel self IP, allow default service, allow none stops self ip ping from working
   tmsh create net self 10.1.6.34 address 10.1.6.34/255.255.255.0 allow-service default vlan flannel_vxlan

   #. Create a static route to Cilium managed pod CIDR network ``10.0.0.0/16`` through tunnel interface ``flannel_vxlan``
   tmsh create net route 10.0.0.0 network 10.0.0.0/16 interface flannel_vxlan

   #. Save sys config
   tmsh save sys config

`HA configuration <https://github.com/mdditt2000/k8s-bigip-ctlr/blob/main/user_guides/k8s-ha/README.md>`_


Enable Cilium VXLAN Tunnel Endpoint (VTEP) integration
======================================================

This feature requires a Linux ``5.4`` kernel (RHEL8/Centos8 with 4.18.x supported also) or later, and is disabled by default. When enabling the VTEP integration, you must also specify the IPs, CIDR ranges and MACs for each VTEP device as part of the configuration.

.. tabs::

    .. group-tab:: Helm

        If you installed Cilium via ``helm install``, you may enable
        the VTEP support with the following command:

        .. parsed-literal::

           helm upgrade cilium |CHART_RELEASE| \
              --namespace kube-system \
              --reuse-values \
              --set vtep.enabled="true" \
              --set vtep.endpoint="10.169.72.34    10.169.72.36" \
              --set vtep.cidr="10.1.6.0/24         10.1.5.0/24" \
              --set vtep.mac="01:50:56:A0:7D:D8    00:50:56:86:6b:28" \
              --set policyEnforcementMode="never"

    .. group-tab:: ConfigMap

       VTEP support can be enabled by setting the
       following options in the ``cilium-config`` ConfigMap:

       .. code-block:: yaml

          enable-vtep:   "true"
          vtep-endpoint: "10.169.72.34        10.169.72.36"
          vtep-cidr:     "10.1.6.0/24         10.1.5.0/24"
          vtep-mac:      "01:50:56:A0:7D:D8   00:50:56:86:6b:28"
          enable-policy: "never"

       Restart Cilium daemonset:

       .. code-block:: bash

          kubectl -n $CILIUM_NAMESPACE rollout restart ds/cilium

How BIG-IP Devices connect to Kubernetes Cluster Pod
----------------------------------------------------

When a BIG-IP device is outside of the Kubernetes Cluster Network, it can still
load balance directly to any Pod in the Cluster.

After CIS is deployed in Kubernetes cluster managed by Cilium, CIS creates fake
FDB entry for each Cilium managed Kubernetes node on BIG-IP

- fake forwarding database (FDB) records based on each Kubernetes Node's Node IP address,
  for example ``0a:0a:xx:xx:xx:xx`` where ``xx`` is based on each Node IP octet;

When BIG-IP send traffic to Kubernetes pod managed by Cilium

first, it looks for if there is route to the pod network
Through route lookup, BIG-IP knows to send traffic to pod network through VXLAN
interface ``/Common/flannel_vxlan``

::

   -----------------------------------------------------------------------------------
   Net::Routes
   Name                Destination         Type       NextHop                Origin
   -----------------------------------------------------------------------------------
   10.0.0.0            10.0.0.0/16         interface  /Common/flannel_vxlan  static

second, according to FDB entries created by CIS, BIG-IP sends ARP broadcast to
each FDB record endpoint, which is Cilium managed Kubernetes node, only the Kubernetes
node that hosting the pod send ARP reply.


.. rubric:: **Example:**

Node1 has the NodeIP address, MAC address, and Pod IP address shown in the table below.

+-------------------------------------------------------------------+
| Kubernetes Node1                                                  |
+===============================================+===================+
| Node IP address                               | 10.169.72.239     |
+-----------------------------------------------+-------------------+
| Pod IP address                                | 10.0.0.130        |
+-----------------------------------------------+-------------------+

CIS use Node IP to create a fake FDB record on the BIG-IP system:

::

   FDB record

   flannel_vxlan {
    records [
       0a:0a:0a:a9:48:ef {
           endpoint 10.169.72.239%0
       }
    ]
   }

When BIG-IP send traffic to Cilium managed pod ``10.0.0.130``, ARP broadcast sends to all the Cilium managed nodes
but only node ``10.169.72.239`` hosting pod ``10.0.0.130`` will send ARP reply for pod ``10.0.0.130``, thus BIG-IP knows pod
``10.0.0.130`` is on node ``10.169.72.239``:

::

   -----------------------------------------------------------------------------------------------
   Net::Arp
   Name           Address        HWaddress          Vlan                   Expire-in-sec  Status
   -----------------------------------------------------------------------------------------------
   10.0.0.130     10.0.0.130     06:a6:6e:b5:69:2c  /Common/flannel_vxlan  289            resolved



How Cilium knows about the BIG-IP device
----------------------------------------

At this point, your BIG-IP device knows how to route to the Kubernetes network, but how does Cilium knows about the BIG-IP device. 
When Cilium VTEP integration feature is enabled, Cilium stores BIG-IP tunnel subnet ``10.1.6.0/24``, BIG-IP vlan ``self-ip``, flannel_vxlan
``MAC`` address in Cilium ipcache map like below, when Cilium managed pod send traffic to subnet ``10.1.6.0/24``, it knows the VTEP endpoint is BIG-IP vlan self-ip ``10.169.72.34`` and use that as VXLAN encapsulation

::

   Cilium ipcache map

   IP PREFIX/ADDRESS   IDENTITY

   10.1.5.0/24         identity=2 encryptkey=0 tunnelendpoint=10.169.72.36
   10.1.6.0/24         identity=2 encryptkey=0 tunnelendpoint=10.169.72.34
   10.0.0.130/32       identity=3 encryptkey=0 tunnelendpoint=0.0.0.0
   0.0.0.0/0           identity=2 encryptkey=0 tunnelendpoint=0.0.0.0



******************************************************
Cilium VXLAN Tunnel Endpoint (VTEP) Integration (beta)
******************************************************

.. include:: ../beta.rst

The VTEP integration allows third party VTEP devices to send and receive traffic to
and from Cilium-managed pods directly using VXLAN. This allows for example external
load balancers like BIG-IP to load balance traffic to Cilium-managed pods using VXLAN.

This document explains how to enable VTEP support and configure Cilium with VTEP
endpoint IPs, CIDRs, and MAC addresses.


.. note::

   This guide assumes that Cilium has been correctly installed in your
   Kubernetes cluster. Please see :ref:`k8s_quick_install` for more
   information. If unsure, run ``cilium status`` and validate that Cilium is up
   and running. This guide also assumes VTEP devices has been configured with
   VTEP endpoint IP, VTEP CIDRs, VTEP MAC addresses (VTEP MAC). The VXLAN network
   identifier (VNI) *must* be configured as VNI ``2``, which represents traffic
   from the VTEP as the world identity. See :ref:`reserved_labels` for more details.

.. warning::

   This feature is in beta, and is currently incompatible with network policy.
   The instructions below will specify to disable network policy in order to enable
   the feature for getting started. This restriction will be lifted when the feature
   graduates from beta. This work is tracked in :gh-issue:`17694`.


