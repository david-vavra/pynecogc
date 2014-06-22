 sysname ${device.fqdn.split('.')[0]}
 clock summer-time CEST repeating 02:00:00 03/25/2012 03:00:00 10/28/2012  01:00:00
#
 undo password-control aging enable
 undo password-control length enable
 undo password-control history enable
 password-control login-attempt 10 exceed unlock
#
 super password level 3 cipher $c$3$/ZsxmRkD2qembU0U7ZFnPMEjZtJl7Q+XVA0jfQ==

 domain default enable tacacs
#
 dns resolve    
 dns server 147.251.4.33
 dns server 147.251.7.38
 dns source-interface LoopBack0
#               
 ipv6           
#               
 ip ttl-expires enable
 ip unreachables enable
 ip icmp-extensions non-compliant
#               
 acl logging frequence 5
#               
 transceiver phony-alarm-disable
#               
 multicast routing-enable
#               
 mpls lsr-id 147.251.243.${device.core_id if device.core_id is not None else 'FIXME'} 
#               
 password-recovery enable
#               
ip vpn-instance CESNET
 route-distinguisher 65080:1
 vpn-target 65080:1 export-extcommunity
 vpn-target 65080:1 import-extcommunity
#               
ip vpn-instance MUNINET
 route-distinguisher 65080:2
 vpn-target 65080:2 export-extcommunity
 vpn-target 65080:2 import-extcommunity
#               
ip vpn-instance TELEFONY
 route-distinguisher 65080:3
 vpn-target 65080:3 export-extcommunity
 vpn-target 65080:3 import-extcommunity
#               
ip vpn-instance CPS
 route-distinguisher 65080:4
 vpn-target 65080:4 export-extcommunity
 vpn-target 65080:4 import-extcommunity
#               
ip vpn-instance USKM
 route-distinguisher 65080:5
 vpn-target 65080:5 export-extcommunity
 vpn-target 65080:5 import-extcommunity
#               
acl number 2000 name DENY-ALL
 rule 10 deny
acl number 2001 name NTP_PEERS
 rule 10 permit source 147.251.7.17 0
 rule 20 permit source 147.251.7.38 0
 rule 30 deny
acl number 2009 name VTY4
 rule 10 permit source 147.251.1.0 0.0.0.63
 rule 20 permit source 147.251.7.0 0.0.0.255
 rule 30 permit source 147.251.243.0 0.0.0.255
 rule 40 permit source 147.251.244.0 0.0.0.255
 rule 50 permit source 10.0.0.16 0.0.255.15
 rule 60 deny logging
acl number 2011 name SNMP_thibkp
 rule 10 permit source 147.251.7.38 0
 rule 20 permit source 147.251.1.36 0
 rule 30 permit source 147.251.7.15 0
 rule 40 permit source 147.251.7.11 0
 rule 50 permit source 147.251.7.10 0
 rule 60 permit source 147.251.7.18 0
 rule 70 permit source 147.251.7.17 0
acl number 2012 name SNMP_G1gaBaps
 rule 10 permit source 147.251.7.38 0
 rule 20 permit source 147.251.1.36 0
 rule 30 permit source 147.251.7.15 0
 rule 40 permit source 147.251.7.11 0
 rule 50 permit source 147.251.7.10 0
 rule 60 permit source 147.251.7.18 0
 rule 70 permit source 147.251.7.17 0
#               
#               
igmp-snooping   
#               
vlan 1          
#               
vlan 10         
 name Local_switch_mgmt
#               
vlan 20         
 name Maintenance
#               
vlan 100        
 name Local_management
#               
mpls
 lsp-trigger all
#
l2vpn
 mpls l2vpn
#
mpls ldp
#               
hwtacacs scheme hwtac
 primary authentication 147.251.7.17
 primary authorization 147.251.7.17
 primary accounting 147.251.7.17
 nas-ip 147.251.243.32
 key authentication cipher $c$3$bm1VVpqZIZvM3U28cINTHMXdWDYd2a9iDFXY9LE6cojCM800qxbD
 key authorization cipher $c$3$s9fi35hnGlurHabMFccPpvj94Nf08ORT5nHRTW0plgstGbS2w1+N
 key accounting cipher $c$3$ARU8HjczzBfvm5AIK+HEd0k5mIiKmo0rcEH8v67HVgAn+V0BQ+oe
 user-name-format without-domain
#               
domain system   
 access-limit disable
 state active   
 idle-cut disable
 self-service-url disable
domain tacacs   
 authentication default hwtacacs-scheme hwtac local
 authorization default hwtacacs-scheme hwtac local
 accounting default hwtacacs-scheme hwtac local
 authentication login hwtacacs-scheme hwtac local
 access-limit disable
 state active   
 idle-cut disable
 self-service-url disable
#               
local-user admin
 password cipher $c$3$ME7WMGgXMN/lq9exDtGUPd7PQe4kBmdLA78eIw==
 service-type ssh terminal
 undo servis-type telnet
#               
 stp mode rstp  
 stp enable     
interface NULL0
#
interface LoopBack0
 ipv6 address 2001:718:801:1::${device.core_id if device.core_id is not None else 'FIXME'}/128
 ip address 147.251.243.${device.core_id if device.core_id is not None else 'FIXME'} 255.255.255.255
 ospfv3 65080 area 0.0.0.100
#               
interface Vlan-interface10
 description Mgmt lokalnich switchu
 ip address 10.0.${device.core_id if device.core_id is not None else 'FIXME'}.33 255.255.255.240
#               
interface Vlan-interface20
 description Pristup pro notebooky
 ip address 10.0.${device.core_id if device.core_id is not None else 'FIXME'}.17 255.255.255.240
#               
interface Vlan-interface100
 description Mgmt UPS a spol.
 ip address 10.0.${device.core_id if device.core_id is not None else 'FIXME'}.1 255.255.255.240
 packet-filter name Vlan-interface100 inbound
 packet-filter name Vlan-interface100 outbound
#
interface FIXME
 port link-mode route
 description FIXME - paterni prvek
 jumboframe enable 9216
 ipv6 address auto
 ipv6 address auto link-local
 ip address 147.251.244.XXX 255.255.255.252
 mpls
 mpls ldp
 ospfv3 65080 area 0.0.0.100
 ospfv3 bfd enable
 ospfv3 mtu-ignore
 ospfv3 network-type p2p
 ospf authentication-mode md5 1 plain XXXXXX
 ospf network-type p2p
 ospf bfd enable
 pim sm
#
interface XXXXX-1/0/26
 port link-mode route
 description FIXME - paterni prvek
 jumboframe enable 9216
 ipv6 address auto
 ipv6 address auto link-local
 ip address 147.251.244.XXX 255.255.255.252
 mpls           
 mpls ldp       
 ospfv3 65080 area 0.0.0.100
 ospfv3 bfd enable
 ospfv3 mtu-ignore
 ospfv3 network-type p2p
 ospf authentication-mode md5 1 plain XXXXXXX
 ospf network-type p2p
 ospf bfd enable
 pim sm
#         
bgp 65080       
 router-id 147.251.243.${device.core_id if device.core_id is not None else 'FIXME'}
 import-route direct
 import-route static
 undo synchronization
 group CORE internal
 peer CORE description MUNI route reflectors
 peer CORE timer keepalive 10 hold 30
 peer CORE password cipher $c$3$xSbctUm1vulIympPyIs7PGFcUQxjH6YNz77X0E4=
 peer CORE connect-interface LoopBack0
 peer 147.251.243.5 group CORE
 peer 147.251.243.5 description c-rect.bb10.muni.cz
 peer 147.251.243.6 group CORE
 peer 147.251.243.6 description c-econ.bb10.muni.cz
 #              
 ipv6-family    
  import-route direct
  import-route static
  undo synchronization
  group CORE-IPv6 internal
  peer CORE-IPv6 description MUNI IPv6 route reflectors
  peer CORE-IPv6 timer keepalive 10 hold 30
  peer CORE-IPv6 password cipher $c$3$xSbctUm1vulIympPyIs7PGFcUQxjH6YNz77X0E4=
  peer CORE-IPv6 connect-interface LoopBack0
  peer 2001:718:801:1::5 group CORE-IPv6
  peer 2001:718:801:1::6 group CORE-IPv6
 #              
 ipv4-family vpn-instance CESNET
  import-route direct
  import-route static
 #              
 ipv4-family vpn-instance MUNINET
  import-route direct
  import-route static
 #              
 ipv4-family vpn-instance TELEFONY
  import-route direct
  import-route static
 #              
 ipv4-family vpn-instance CPS
  import-route direct
  import-route static
 # 
 ipv4-family vpn-instance USKM
  import-route direct
  import-route static
 #              
 ipv6-family vpn-instance CESNET
  import-route direct
  import-route static
 #              
 ipv6-family vpn-instance MUNINET
  import-route direct
  import-route static
 #              
 ipv6-family vpn-instance TELEFONY
  import-route direct
  import-route static
 #              
 ipv6-family vpn-instance CPS
  import-route direct
  import-route static
 #              
 ipv6-family vpn-instance USKM
  import-route direct
  import-route static
 #              
 ipv4-family vpnv4
  peer 147.251.243.5 enable
  peer 147.251.243.6 enable
 #              
 ipv6-family vpnv6
  peer 147.251.243.5 enable
  peer 147.251.243.6 enable
#               
ospf 100 router-id 147.251.243.${device.core_id if device.core_id is not None else 'FIXME'}
 area 0.0.0.100 
  network 147.251.244.XXX 0.0.0.3
  network 147.251.243.YY 0.0.0.0
  network 147.251.244.XXX 0.0.0.3
  network 147.251.244.XXX 0.0.0.3
#               
ospfv3 65080    
 router-id 147.251.243.${device.core_id if device.core_id is not None else 'FIXME'}
 area 0.0.0.100 
#               
pim
#
 ip route-static 10.0.0.1 255.255.255.255 NULL0 description RTBH
 info-center source default channel 0 log level debugging
 info-center source SNMP channel 2
 undo info-center source default channel 2
 info-center source default channel 4 log level debugging debug state on
 info-center source ACL channel 4 log level debugging debug state on
 info-center loghost 147.251.7.17 facility local2
 info-center console channel 1
#               
 snmp-agent     
 snmp-agent community read 10GiBAPS  acl 2012
 snmp-agent community write th1ng0lbkp  acl 2011
 snmp-agent sys-info version all
 snmp-agent mib-view included admin iso
#               
 header login ^ 
-- ${device.fqdn} --
^ 
#               
 ip urpf loose  
#               
 dhcp enable    
#
 ntp-service access peer 2001
 ntp-service access server 2000
 ntp-service access synchronization 2000
 ntp-service access query 2000               
 ntp-service unicast-server 147.251.7.17
 ntp-service unicast-server 147.251.7.38
#               
 ssh server enable
 ssh client authentication server 147.251.7.17 assign publickey 147.251.7.17
#               
 load xml-configuration
#               
 load tr069-configuration
#               
user-interface aux 0
 authentication-mode scheme
user-interface vty 0 15
 acl 2009 inbound
 acl ipv6 2009 inbound
 authentication-mode scheme
 protocol inbound ssh
#               

