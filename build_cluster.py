#################################################################################
# This is a F5 Python Script to build a Two-Node Sync-Failover Cluster
#
# v0.1 - 15.04.2017
# Tested with 
#   - Python Version 2.7.13 and 
#   - BIG-IP Software Version 12.1.2 Build 0.0.249
#
# (c) Daniel Tremmel, NTT Security
#
# Requirements: 
#   - Python modules: requests, base64, time, sys
#
# Tasks:
#   - create VLANs
#   - create Self-IPs
#   - create Routes
#   - create Sync-Failover-Cluster
#   - create UCS Archive
#################################################################################

import requests, base64, time, sys

# disable 'insecure SSL certificate' warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#################################################################################
# define Environment Variables
#################################################################################
# General
var_ip_mgmt_n1 = "10.1.1.211"				# MGMT IP Address of Node 1
var_ip_mgmt_n2 = "10.1.1.212"				# MGMT IP Address of Node 2
var_fqdn_n1 = "node1.vlab.local"			# FQDN of Node 1
var_fqdn_n2 = "node2.vlab.local"			# FQDN of Node 1
var_admin_user = "admin"					# Administrator username
var_admin_pw = "admin"						# Administrator password
var_device_group = "failover-cluster-01"	# Sync-Failover Group Name
var_coe = "no"								# Continue on Error? [ yes / no ]
# Interfaces
var_int_external = "1.1"					# Interface for VLAN 'External'
var_int_internal = "1.2"					# Interface for VLAN 'Internal'
var_int_ha = "1.3"							# Interface for VLAN 'HA'
# Self-IPs
var_self_external_n1 = "10.1.10.211"
var_self_external_n2 = "10.1.10.212"
var_self_external_floating = "10.1.10.213"
var_self_internal_n1 = "10.1.20.211"
var_self_internal_n2 = "10.1.20.212"
var_self_internal_floating = "10.1.20.213"
var_self_ha_n1 = "192.168.33.211"
var_self_ha_n2 = "192.168.33.212"
# Default GW
var_default_gw = "10.1.10.2"

#################################################################################
# setup Authorization
#################################################################################
var_b64string = base64.b64encode(bytes(var_admin_user + ':' + var_admin_pw))
var_auth_header = "Basic " + var_b64string

#################################################################################
# create VLANs
#################################################################################
print("1.) create VLANs")

# Node 1 - External
print("    - creating VLAN 'External' on Node 1")
u_vlan_external_n1 = "https://" + var_ip_mgmt_n1 + "/mgmt/tm/net/vlan"
p_vlan_external_n1 = "{\n  \"name\": \"External\",\n  \"partition\": \"Common\",\n  \"autoLasthop\": \"default\",\n  \"cmpHash\": \"default\",\n  \"mtu\": \"1500\",\n  \"interfaces\": \n    [ \n        {\n            \"name\":\"" + var_int_external + "\",\n            \"tagged\":false\n        }\n    ]\n}"
h_vlan_external_n1 = {
    'authorization': var_auth_header,
    'content-type': "application/json",
    'cache-control': "no-cache",
    }
r_vlan_external_n1 = requests.request("POST", u_vlan_external_n1, data=p_vlan_external_n1, headers=h_vlan_external_n1, verify=False)
if r_vlan_external_n1.text.startswith('{"code') and var_coe == "yes": 
	print("Error message: " + r_vlan_external_n1.text)
	print("Continue...")
elif r_vlan_external_n1.text.startswith('{"code') and var_coe == "no":
	sys.exit("Script stopped, error message: " + r_vlan_external_n1.text)
else:
	print("      -> done!")

# Node 2 - External
print("    - creating VLAN 'External' on Node 2")
u_vlan_external_n2 = "https://" + var_ip_mgmt_n2 + "/mgmt/tm/net/vlan"
p_vlan_external_n2 = "{\n  \"name\": \"External\",\n  \"partition\": \"Common\",\n  \"autoLasthop\": \"default\",\n  \"cmpHash\": \"default\",\n  \"mtu\": \"1500\",\n  \"interfaces\": \n    [ \n        {\n            \"name\":\"" + var_int_external + "\",\n            \"tagged\":false\n        }\n    ]\n}"
h_vlan_external_n2 = {
    'authorization': var_auth_header,
    'content-type': "application/json",
    'cache-control': "no-cache",
    }
r_vlan_external_n2 = requests.request("POST", u_vlan_external_n2, data=p_vlan_external_n2, headers=h_vlan_external_n2, verify=False)
if r_vlan_external_n2.text.startswith('{"code') and var_coe == "yes": 
	print("Error message: " + r_vlan_external_n2.text)
	print("Continue...")
elif r_vlan_external_n2.text.startswith('{"code') and var_coe == "no":
	sys.exit("Script stopped, error message: " + r_vlan_external_n2.text)
else:
	print("      -> done!")

# Node 1 - Internal
print("    - creating VLAN 'Internal' on Node 1")
u_vlan_internal_n1 = "https://" + var_ip_mgmt_n1 + "/mgmt/tm/net/vlan"
p_vlan_internal_n1 = "{\n  \"name\": \"Internal\",\n  \"partition\": \"Common\",\n  \"autoLasthop\": \"default\",\n  \"cmpHash\": \"default\",\n  \"mtu\": \"1500\",\n  \"interfaces\": \n    [ \n        {\n            \"name\":\"" + var_int_internal + "\",\n            \"tagged\":false\n        }\n    ]\n}"
h_vlan_internal_n1 = {
    'authorization': var_auth_header,
    'content-type': "application/json",
    'cache-control': "no-cache",
    }
r_vlan_internal_n1 = requests.request("POST", u_vlan_internal_n1, data=p_vlan_internal_n1, headers=h_vlan_internal_n1, verify=False)
if r_vlan_internal_n1.text.startswith('{"code') and var_coe == "yes": 
	print("Error message: " + r_vlan_internal_n1.text)
	print("Continue...")
elif r_vlan_internal_n1.text.startswith('{"code') and var_coe == "no":
	sys.exit("Script stopped, error message: " + r_vlan_internal_n1.text)
else:
	print("      -> done!")

# Node 2 - Internal
print("    - creating VLAN 'Internal' on Node 2")
u_vlan_internal_n2 = "https://" + var_ip_mgmt_n2 + "/mgmt/tm/net/vlan"
p_vlan_internal_n2 = "{\n  \"name\": \"Internal\",\n  \"partition\": \"Common\",\n  \"autoLasthop\": \"default\",\n  \"cmpHash\": \"default\",\n  \"mtu\": \"1500\",\n  \"interfaces\": \n    [ \n        {\n            \"name\":\"" + var_int_internal + "\",\n            \"tagged\":false\n        }\n    ]\n}"
h_vlan_internal_n2 = {
    'authorization': var_auth_header,
    'content-type': "application/json",
    'cache-control': "no-cache",
    }
r_vlan_internal_n2 = requests.request("POST", u_vlan_internal_n2, data=p_vlan_internal_n2, headers=h_vlan_internal_n2, verify=False)
if r_vlan_internal_n2.text.startswith('{"code') and var_coe == "yes": 
	print("Error message: " + r_vlan_internal_n2.text)
	print("Continue...")
elif r_vlan_internal_n2.text.startswith('{"code') and var_coe == "no":
	sys.exit("Script stopped, error message: " + r_vlan_internal_n2.text)
else:
	print("      -> done!")

# Node 1 - HA
print("    - creating VLAN 'HA' on Node 1")
u_vlan_ha_n1 = "https://" + var_ip_mgmt_n1 + "/mgmt/tm/net/vlan"
p_vlan_ha_n1 = "{\n  \"name\": \"HA\",\n  \"partition\": \"Common\",\n  \"autoLasthop\": \"default\",\n  \"cmpHash\": \"default\",\n  \"mtu\": \"1500\",\n  \"interfaces\": \n    [ \n        {\n            \"name\":\"" + var_int_ha + "\",\n            \"tagged\":false\n        }\n    ]\n}"
h_vlan_ha_n1 = {
    'authorization': var_auth_header,
    'content-type': "application/json",
    'cache-control': "no-cache",
    }
r_vlan_ha_n1 = requests.request("POST", u_vlan_ha_n1, data=p_vlan_ha_n1, headers=h_vlan_ha_n1, verify=False)
if r_vlan_ha_n1.text.startswith('{"code') and var_coe == "yes": 
	print("Error message: " + r_vlan_ha_n1.text)
	print("Continue...")
elif r_vlan_ha_n1.text.startswith('{"code') and var_coe == "no":
	sys.exit("Script stopped, error message: " + r_vlan_ha_n1.text)
else:
	print("      -> done!")

# Node 2 - HA
print("    - creating VLAN 'HA' on Node 2")
u_vlan_ha_n2 = "https://" + var_ip_mgmt_n2 + "/mgmt/tm/net/vlan"
p_vlan_ha_n2 = "{\n  \"name\": \"HA\",\n  \"partition\": \"Common\",\n  \"autoLasthop\": \"default\",\n  \"cmpHash\": \"default\",\n  \"mtu\": \"1500\",\n  \"interfaces\": \n    [ \n        {\n            \"name\":\"" + var_int_ha + "\",\n            \"tagged\":false\n        }\n    ]\n}"
h_vlan_ha_n2 = {
    'authorization': var_auth_header,
    'content-type': "application/json",
    'cache-control': "no-cache",
    }
r_vlan_ha_n2 = requests.request("POST", u_vlan_ha_n2, data=p_vlan_ha_n2, headers=h_vlan_ha_n2, verify=False)
if r_vlan_ha_n2.text.startswith('{"code') and var_coe == "yes": 
	print("Error message: " + r_vlan_ha_n2.text)
	print("Continue...")
elif r_vlan_ha_n2.text.startswith('{"code') and var_coe == "no":
	sys.exit("Script stopped, error message: " + r_vlan_ha_n2.text)
else:
	print("      -> done!")

#################################################################################
# create Self-IPs
#################################################################################
print("2.) create Self-IPs")

# Node 1 - External
print("    - creating SelfIP 'External' on Node 1")
u_self_external_n1 = "https://" + var_ip_mgmt_n1 + "/mgmt/tm/net/self/"
p_self_external_n1 = "{\n   \"name\": \"SelfIP-External\",\n   \"partition\": \"Common\",\n   \"address\": \"" + var_self_external_n1 + "/24\",\n   \"floating\": \"disabled\",\n   \"trafficGroup\": \"/Common/traffic-group-local-only\",\n   \"vlan\": \"/Common/External\",\n   \"allowService\": [\n     \"default\"\n   ]\n}"
h_self_external_n1 = {
    'content-type': "application/json",
    'authorization': var_auth_header,
    'cache-control': "no-cache",
    }
r_self_external_n1 = requests.request("POST", u_self_external_n1, data=p_self_external_n1, headers=h_self_external_n1, verify=False)
if r_self_external_n1.text.startswith('{"code') and var_coe == "yes": 
	print("Error message: " + r_self_external_n1.text)
	print("Continue...")
elif r_self_external_n1.text.startswith('{"code') and var_coe == "no":
	sys.exit("Script stopped, error message: " + r_self_external_n1.text)
else:
	print("      -> done!")

# Node 1 - External Floating
print("    - creating SelfIP 'External-Floating' on Node 1")
u_self_external_floating = "https://" + var_ip_mgmt_n1 + "/mgmt/tm/net/self/"
p_self_external_floating = "{\n   \"name\": \"SelfIP-External-Floating\",\n   \"partition\": \"Common\",\n   \"address\": \"" + var_self_external_floating + "/24\",\n   \"floating\": \"enabled\",\n   \"trafficGroup\": \"/Common/traffic-group-1\",\n   \"vlan\": \"/Common/External\",\n   \"allowService\": [\n     \"default\"\n   ]\n}"
h_self_external_floating = {
    'content-type': "application/json",
    'authorization': var_auth_header,
    'cache-control': "no-cache",
    }
r_self_external_floating = requests.request("POST", u_self_external_floating, data=p_self_external_floating, headers=h_self_external_floating, verify=False)
if r_self_external_floating.text.startswith('{"code') and var_coe == "yes": 
	print("Error message: " + r_self_external_floating.text)
	print("Continue...")
elif r_self_external_floating.text.startswith('{"code') and var_coe == "no":
	sys.exit("Script stopped, error message: " + r_self_external_floating.text)
else:
	print("      -> done!")

# Node 2 - External
print("    - creating SelfIP 'External' on Node 2")
u_self_external_n2 = "https://" + var_ip_mgmt_n2 + "/mgmt/tm/net/self/"
p_self_external_n2 = "{\n   \"name\": \"SelfIP-External\",\n   \"partition\": \"Common\",\n   \"address\": \"" + var_self_external_n2 + "/24\",\n   \"floating\": \"disabled\",\n   \"trafficGroup\": \"/Common/traffic-group-local-only\",\n   \"vlan\": \"/Common/External\",\n   \"allowService\": [\n     \"default\"\n   ]\n}"
h_self_external_n2 = {
    'content-type': "application/json",
    'authorization': var_auth_header,
    'cache-control': "no-cache",
    }
r_self_external_n2 = requests.request("POST", u_self_external_n2, data=p_self_external_n2, headers=h_self_external_n2, verify=False)
if r_self_external_n2.text.startswith('{"code') and var_coe == "yes": 
	print("Error message: " + r_self_external_n2.text)
	print("Continue...")
elif r_self_external_n2.text.startswith('{"code') and var_coe == "no":
	sys.exit("Script stopped, error message: " + r_self_external_n2.text)
else:
	print("      -> done!")

# Node 1 - Internal
print("    - creating SelfIP 'Internal' on Node 1")
u_self_internal_n1 = "https://" + var_ip_mgmt_n1 + "/mgmt/tm/net/self/"
p_self_internal_n1 = "{\n   \"name\": \"SelfIP-Internal\",\n   \"partition\": \"Common\",\n   \"address\": \"" + var_self_internal_n1 + "/24\",\n   \"floating\": \"disabled\",\n   \"trafficGroup\": \"/Common/traffic-group-local-only\",\n   \"vlan\": \"/Common/Internal\",\n   \"allowService\": [\n     \"default\"\n   ]\n}"
h_self_internal_n1 = {
    'content-type': "application/json",
    'authorization': var_auth_header,
    'cache-control': "no-cache",
    }
r_self_internal_n1 = requests.request("POST", u_self_internal_n1, data=p_self_internal_n1, headers=h_self_internal_n1, verify=False)
if r_self_internal_n1.text.startswith('{"code') and var_coe == "yes": 
	print("Error message: " + r_self_internal_n1.text)
	print("Continue...")
elif r_self_internal_n1.text.startswith('{"code') and var_coe == "no":
	sys.exit("Script stopped, error message: " + r_self_internal_n1.text)
else:
	print("      -> done!")

# Node 1 - Internal Floating
print("    - creating SelfIP 'Internal-Floating' on Node 1")
u_self_internal_floating = "https://" + var_ip_mgmt_n1 + "/mgmt/tm/net/self/"
p_self_internal_floating = "{\n   \"name\": \"SelfIP-Internal-Floating\",\n   \"partition\": \"Common\",\n   \"address\": \"" + var_self_internal_floating + "/24\",\n   \"floating\": \"enabled\",\n   \"trafficGroup\": \"/Common/traffic-group-1\",\n   \"vlan\": \"/Common/Internal\",\n   \"allowService\": [\n     \"default\"\n   ]\n}"
h_self_internal_floating = {
    'content-type': "application/json",
    'authorization': var_auth_header,
    'cache-control': "no-cache",
    }
r_self_internal_floating = requests.request("POST", u_self_internal_floating, data=p_self_internal_floating, headers=h_self_internal_floating, verify=False)
if r_self_internal_floating.text.startswith('{"code') and var_coe == "yes": 
	print("Error message: " + r_self_internal_floating.text)
	print("Continue...")
elif r_self_internal_floating.text.startswith('{"code') and var_coe == "no":
	sys.exit("Script stopped, error message: " + r_self_internal_floating.text)
else:
	print("      -> done!")

# Node 2 - Internal
print("    - creating SelfIP 'Internal' on Node 2")
u_self_internal_n2 = "https://" + var_ip_mgmt_n2 + "/mgmt/tm/net/self/"
p_self_internal_n2 = "{\n   \"name\": \"SelfIP-Internal\",\n   \"partition\": \"Common\",\n   \"address\": \"" + var_self_internal_n2 + "/24\",\n   \"floating\": \"disabled\",\n   \"trafficGroup\": \"/Common/traffic-group-local-only\",\n   \"vlan\": \"/Common/Internal\",\n   \"allowService\": [\n     \"default\"\n   ]\n}"
h_self_internal_n2 = {
    'content-type': "application/json",
    'authorization': var_auth_header,
    'cache-control': "no-cache",
    }
r_self_internal_n2 = requests.request("POST", u_self_internal_n2, data=p_self_internal_n2, headers=h_self_internal_n2, verify=False)
if r_self_internal_n2.text.startswith('{"code') and var_coe == "yes": 
	print("Error message: " + r_self_internal_n2.text)
	print("Continue...")
elif r_self_internal_n2.text.startswith('{"code') and var_coe == "no":
	sys.exit("Script stopped, error message: " + r_self_internal_n2.text)
else:
	print("      -> done!")

# Node 1 - HA
print("    - creating SelfIP 'HA' on Node 1")
u_self_ha_n1 = "https://" + var_ip_mgmt_n1 + "/mgmt/tm/net/self/"
p_self_ha_n1 = "{\n   \"name\": \"SelfIP-HA\",\n   \"partition\": \"Common\",\n   \"address\": \"" + var_self_ha_n1 + "/24\",\n   \"floating\": \"disabled\",\n   \"trafficGroup\": \"/Common/traffic-group-local-only\",\n   \"vlan\": \"/Common/HA\",\n   \"allowService\": [\n     \"default\"\n   ]\n}"
h_self_ha_n1 = {
    'content-type': "application/json",
    'authorization': var_auth_header,
    'cache-control': "no-cache",
    }
r_self_ha_n1 = requests.request("POST", u_self_ha_n1, data=p_self_ha_n1, headers=h_self_ha_n1, verify=False)
if r_self_ha_n1.text.startswith('{"code') and var_coe == "yes": 
	print("Error message: " + r_self_ha_n1.text)
	print("Continue...")
elif r_self_ha_n1.text.startswith('{"code') and var_coe == "no":
	sys.exit("Script stopped, error message: " + r_self_ha_n1.text)
else:
	print("      -> done!")

# Node 2 - HA
print("    - creating SelfIP 'HA' on Node 2")
u_self_ha_n2 = "https://" + var_ip_mgmt_n2 + "/mgmt/tm/net/self/"
p_self_ha_n2 = "{\n   \"name\": \"SelfIP-HA\",\n   \"partition\": \"Common\",\n   \"address\": \"" + var_self_ha_n2 + "/24\",\n   \"floating\": \"disabled\",\n   \"trafficGroup\": \"/Common/traffic-group-local-only\",\n   \"vlan\": \"/Common/HA\",\n   \"allowService\": [\n     \"default\"\n   ]\n}"
h_self_ha_n2 = {
    'content-type': "application/json",
    'authorization': var_auth_header,
    'cache-control': "no-cache",
    }
r_self_ha_n2 = requests.request("POST", u_self_ha_n2, data=p_self_ha_n2, headers=h_self_ha_n2, verify=False)
if r_self_ha_n2.text.startswith('{"code') and var_coe == "yes": 
	print("Error message: " + r_self_ha_n2.text)
	print("Continue...")
elif r_self_ha_n2.text.startswith('{"code') and var_coe == "no":
	sys.exit("Script stopped, error message: " + r_self_ha_n2.text)
else:
	print("      -> done!")

#################################################################################
# create Routes
#################################################################################
print("3.) create Routes")

# Node 1 - Default GW
print("    - setting Default Gateway on Node 1")
u_defaultgw_n1= "https://" + var_ip_mgmt_n1 + "/mgmt/tm/net/route"
p_defaultgw_n1 = "{\n  \"name\": \"Default_GW\",\n  \"partition\": \"Common\",\n  \"gw\": \"" + var_default_gw + "\",\n  \"mtu\": 0,\n  \"network\": \"0.0.0.0/0\"\n}"
h_defaultgw_n1 = {
    'content-type': "application/json",
    'authorization': var_auth_header,
    'cache-control': "no-cache",
    }
r_defaultgw_n1 = requests.request("POST", u_defaultgw_n1, data=p_defaultgw_n1, headers=h_defaultgw_n1, verify=False)
if r_defaultgw_n1.text.startswith('{"code') and var_coe == "yes": 
	print("Error message: " + r_defaultgw_n1.text)
	print("Continue...")
elif r_defaultgw_n1.text.startswith('{"code') and var_coe == "no":
	sys.exit("Script stopped, error message: " + r_defaultgw_n1.text)
else:
	print("      -> done!")

# Node 2 - Default GW
print("    - setting Default Gateway on Node 2")
u_defaultgw_n2= "https://" + var_ip_mgmt_n2 + "/mgmt/tm/net/route"
p_defaultgw_n2 = "{\n  \"name\": \"Default_GW\",\n  \"partition\": \"Common\",\n  \"gw\": \"" + var_default_gw + "\",\n  \"mtu\": 0,\n  \"network\": \"0.0.0.0/0\"\n}"
h_defaultgw_n2 = {
    'content-type': "application/json",
    'authorization': var_auth_header,
    'cache-control': "no-cache",
    }
r_defaultgw_n2 = requests.request("POST", u_defaultgw_n2, data=p_defaultgw_n2, headers=h_defaultgw_n2, verify=False)
if r_defaultgw_n2.text.startswith('{"code') and var_coe == "yes": 
	print("Error message: " + r_defaultgw_n2.text)
	print("Continue...")
elif r_defaultgw_n2.text.startswith('{"code') and var_coe == "no":
	sys.exit("Script stopped, error message: " + r_defaultgw_n2.text)
else:
	print("      -> done!")

#################################################################################
# create Sync-Failover-Cluster
#################################################################################
print("4.) create Sync-Failover-Cluster")

# Node 1 - Set CMI Device Parameters
print("    - setting CMI Device Parameters on Node 1")
u_cmi_parm_n1= "https://" + var_ip_mgmt_n1 + "/mgmt/tm/cm/device/~Common~" + var_fqdn_n1 + ""
p_cmi_parm_n1 = "{\n  \"configsyncIp\": \"" + var_self_ha_n1 + "\",\n  \"mirrorIp\": \"" + var_self_ha_n1 + "\",\n  \"mirrorSecondaryIp\": \"any6\",\n  \"unicastAddress\": [\n    {\n      \"effectiveIp\": \"" + var_self_ha_n1 + "\",\n      \"effectivePort\": 1026,\n      \"ip\": \"" + var_self_ha_n1 + "\",\n      \"port\": 1026\n    }\n  ]\n}"
h_cmi_parm_n1 = {
    'content-type': "application/json",
    'authorization': var_auth_header,
    'cache-control': "no-cache",
    }
r_cmi_parm_n1 = requests.request("PATCH", u_cmi_parm_n1, data=p_cmi_parm_n1, headers=h_cmi_parm_n1, verify=False)
if r_cmi_parm_n1.text.startswith('{"code') and var_coe == "yes": 
	print("Error message: " + r_cmi_parm_n1.text)
	print("Continue...")
elif r_cmi_parm_n1.text.startswith('{"code') and var_coe == "no":
	sys.exit("Script stopped, error message: " + r_cmi_parm_n1.text)
else:
	print("      -> done!")

# Node 2 - Set CMI Device Parameters
print("    - setting CMI Device Parameters on Node 2")
u_cmi_parm_n2= "https://" + var_ip_mgmt_n2 + "/mgmt/tm/cm/device/~Common~" + var_fqdn_n2 + ""
p_cmi_parm_n2 = "{\n  \"configsyncIp\": \"" + var_self_ha_n2 + "\",\n  \"mirrorIp\": \"" + var_self_ha_n2 + "\",\n  \"mirrorSecondaryIp\": \"any6\",\n  \"unicastAddress\": [\n    {\n      \"effectiveIp\": \"" + var_self_ha_n2 + "\",\n      \"effectivePort\": 1026,\n      \"ip\": \"" + var_self_ha_n2 + "\",\n      \"port\": 1026\n    }\n  ]\n}"
h_cmi_parm_n2 = {
    'content-type': "application/json",
    'authorization': var_auth_header,
    'cache-control': "no-cache",
    }
r_cmi_parm_n2 = requests.request("PATCH", u_cmi_parm_n2, data=p_cmi_parm_n2, headers=h_cmi_parm_n2, verify=False)
if r_cmi_parm_n2.text.startswith('{"code') and var_coe == "yes": 
	print("Error message: " + r_cmi_parm_n2.text)
	print("Continue...")
elif r_cmi_parm_n2.text.startswith('{"code') and var_coe == "no":
	sys.exit("Script stopped, error message: " + r_cmi_parm_n2.text)
else:
	print("      -> done!")

# Add Node 2 to CMI Trust on Node 1
print("    - adding Node 2 to Device Trust")
u_cmi_addtrust= "https://" + var_ip_mgmt_n1 + "/mgmt/tm/cm/add-to-trust"
p_cmi_addtrust = "{\n    \"command\":\"run\",\n    \"name\":\"Root\",\n    \"caDevice\":true,\n    \"device\":\"" + var_self_ha_n2 + "\",\n    \"deviceName\":\"" + var_fqdn_n2 + "\",\n    \"username\":\"" + var_admin_user + "\",\n    \"password\":\"" + var_admin_pw + "\"\n}"
h_cmi_addtrust = {
    'content-type': "application/json",
    'authorization': var_auth_header,
    'cache-control': "no-cache",
    }
r_cmi_addtrust = requests.request("POST", u_cmi_addtrust, data=p_cmi_addtrust, headers=h_cmi_addtrust, verify=False)
if r_cmi_addtrust.text.startswith('{"code') and var_coe == "yes": 
	print("Error message: " + r_cmi_addtrust.text)
	print("Continue...")
elif r_cmi_addtrust.text.startswith('{"code') and var_coe == "no":
	sys.exit("Script stopped, error message: " + r_cmi_addtrust.text)
else:
	print("      -> done!")

# Create Device Group
print("    - creating Device Group '" + var_device_group + "'")
u_cmi_createdg= "https://" + var_ip_mgmt_n1 + "/mgmt/tm/cm/device-group"
p_cmi_createdg = "{\n    \"name\":\"" + var_device_group + "\",\n    \"type\":\"sync-failover\",\n    \"autoSync\":\"enabled\",\n    \"devices\": [ \"" + var_fqdn_n1 + "\",\"" + var_fqdn_n2 + "\" ]\n}"
h_cmi_createdg = {
    'content-type': "application/json",
    'authorization': var_auth_header,
    'cache-control': "no-cache",
    }
r_cmi_createdg = requests.request("POST", u_cmi_createdg, data=p_cmi_createdg, headers=h_cmi_createdg, verify=False)
if r_cmi_createdg.text.startswith('{"code') and var_coe == "yes": 
	print("Error message: " + r_cmi_createdg.text)
	print("Continue...")
elif r_cmi_createdg.text.startswith('{"code') and var_coe == "no":
	sys.exit("Script stopped, error message: " + r_cmi_createdg.text)
else:
	print("      -> done!")

# Do the initial sync
print("    - performing initial sync")
u_cmi_initialsync = "https://" + var_ip_mgmt_n1 + "/mgmt/tm/cm"
p_cmi_initialsync = "{\n    \"command\":\"run\",\n    \"utilCmdArgs\":\"config-sync to-group " + var_device_group + "\"\n}"
h_cmi_initialsync = {
    'content-type': "application/json",
    'authorization': var_auth_header,
    'cache-control': "no-cache",
    }
r_cmi_initialsync = requests.request("POST", u_cmi_initialsync, data=p_cmi_initialsync, headers=h_cmi_initialsync, verify=False)
if r_cmi_initialsync.text.startswith('{"code') and var_coe == "yes": 
	print(r_cmi_initialsync.text)
	print("continue...")
elif r_cmi_initialsync.text.startswith('{"code') and var_coe == "no":
	sys.exit("Script stopped, error message: " + r_cmi_initialsync.text)
else:
	print("      -> done!")

time.sleep(10) # wait 10 seconds for the sync process to finish

# Sync Configuration from Node 1 to Group
print("    - syncing Configuration from Node 1 to Group")
u_cmi_sync_n1togroup = "https://" + var_ip_mgmt_n1 + "/mgmt/tm/cm"
p_cmi_sync_n1togroup = "{\n    \"command\":\"run\",\n    \"utilCmdArgs\":\"config-sync to-group " + var_device_group + "\"\n}"
h_cmi_sync_n1togroup = {
    'content-type': "application/json",
    'authorization': var_auth_header,
    'cache-control': "no-cache",
    }
r_cmi_sync_n1togroup = requests.request("POST", u_cmi_sync_n1togroup, data=p_cmi_sync_n1togroup, headers=h_cmi_sync_n1togroup, verify=False)
if r_cmi_sync_n1togroup.text.startswith('{"code') and var_coe == "yes": 
	print("Error message: " + r_cmi_sync_n1togroup.text)
	print("Continue...")
elif r_cmi_sync_n1togroup.text.startswith('{"code') and var_coe == "no":
	sys.exit("Script stopped, error message: " + r_cmi_sync_n1togroup.text)
else:
	print("      -> done!")

#################################################################################
# create UCS Archive
#################################################################################
print("5.) create UCS Archive")

# Node 1
print("    - creating UCS Archive for Node 1")
u_create_ucs_n1 = "https://" + var_ip_mgmt_n1 + "/mgmt/tm/sys/ucs"
p_create_ucs_n1 = "{\n    \"command\":\"save\",\n    \"name\":\"backup_" + var_fqdn_n1 + "_" + time.strftime("%Y-%m-%d") + ".ucs\"\n}"
h_create_ucs_n1 = {
    'content-type': "application/json",
    'authorization': var_auth_header,
    'cache-control': "no-cache",
    }
r_create_ucs_n1 = requests.request("POST", u_create_ucs_n1, data=p_create_ucs_n1, headers=h_create_ucs_n1, verify=False)
if r_create_ucs_n1.text.startswith('{"code') and var_coe == "yes": 
	print(r_create_ucs_n1.text)
	print("continue...")
elif r_create_ucs_n1.text.startswith('{"code') and var_coe == "no":
	sys.exit("Script stopped, error message: " + r_create_ucs_n1.text)
else:
	print("      -> done!")

# Node 2
print("    - creating UCS Archive for Node 2")
u_create_ucs_n2 = "https://" + var_ip_mgmt_n2 + "/mgmt/tm/sys/ucs"
p_create_ucs_n2 = "{\n    \"command\":\"save\",\n    \"name\":\"backup_" + var_fqdn_n2 + "_" + time.strftime("%Y-%m-%d") + ".ucs\"\n}"
h_create_ucs_n2 = {
    'content-type': "application/json",
    'authorization': var_auth_header,
    'cache-control': "no-cache",
    }
r_create_ucs_n2 = requests.request("POST", u_create_ucs_n2, data=p_create_ucs_n2, headers=h_create_ucs_n2, verify=False)
if r_create_ucs_n2.text.startswith('{"code') and var_coe == "yes": 
	print(r_create_ucs_n2.text)
	print("continue...")
elif r_create_ucs_n2.text.startswith('{"code') and var_coe == "no":
	sys.exit("Script stopped, error message: " + r_create_ucs_n2.text)
else:
	print("      -> done!")

#################################################################################
# Finished
#################################################################################
print("-----------------")
print("-   Finished!   -")
print("-----------------")