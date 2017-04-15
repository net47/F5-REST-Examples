#################################################################################
# This is a F5 Python Script to configure a standalone BIG-IP VE
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
var_ip_mgmt = "10.1.1.245"					# MGMT IP Address
var_fqdn = "bigipA.f5demo.com"				# FQDN
var_admin_user = "admin"					# Administrator username
var_admin_pw = "admin"						# Administrator password
var_coe = "no"								# Continue on Error? [ yes / no ]
# Interfaces
var_int_external = "1.1"					# Interface for VLAN 'External'
var_int_internal = "1.2"					# Interface for VLAN 'Internal'
var_int_vmware = "1.3"						# Interface for VLAN 'VMware_NAT'
# Self-IPs
var_self_external = "10.1.10.241"
var_self_internal = "10.1.20.241"
var_self_vmware = "192.168.58.241"
# Default GW
var_default_gw = "192.168.58.2"

#################################################################################
# setup Authorization
#################################################################################
var_b64string = base64.b64encode(bytes(var_admin_user + ':' + var_admin_pw))
var_auth_header = "Basic " + var_b64string

#################################################################################
# create VLANs
#################################################################################
print("1.) create VLANs")

# External
print("    - creating VLAN 'External'")
u_vlan_external = "https://" + var_ip_mgmt + "/mgmt/tm/net/vlan"
p_vlan_external = "{\n  \"name\": \"External\",\n  \"partition\": \"Common\",\n  \"autoLasthop\": \"default\",\n  \"cmpHash\": \"default\",\n  \"mtu\": \"1500\",\n  \"interfaces\": \n    [ \n        {\n            \"name\":\"" + var_int_external + "\",\n            \"tagged\":false\n        }\n    ]\n}"
h_vlan_external = {
    'authorization': var_auth_header,
    'content-type': "application/json",
    'cache-control': "no-cache",
    }
r_vlan_external = requests.request("POST", u_vlan_external, data=p_vlan_external, headers=h_vlan_external, verify=False)
if r_vlan_external.text.startswith('{"code') and var_coe == "yes": 
	print("Error message: " + r_vlan_external.text)
	print("Continue...")
elif r_vlan_external.text.startswith('{"code') and var_coe == "no":
	sys.exit("Script stopped, error message: " + r_vlan_external.text)
else:
	print("      -> done!")

# Internal
print("    - creating VLAN 'Internal'")
u_vlan_internal = "https://" + var_ip_mgmt + "/mgmt/tm/net/vlan"
p_vlan_internal = "{\n  \"name\": \"Internal\",\n  \"partition\": \"Common\",\n  \"autoLasthop\": \"default\",\n  \"cmpHash\": \"default\",\n  \"mtu\": \"1500\",\n  \"interfaces\": \n    [ \n        {\n            \"name\":\"" + var_int_internal + "\",\n            \"tagged\":false\n        }\n    ]\n}"
h_vlan_internal = {
    'authorization': var_auth_header,
    'content-type': "application/json",
    'cache-control': "no-cache",
    }
r_vlan_internal = requests.request("POST", u_vlan_internal, data=p_vlan_internal, headers=h_vlan_internal, verify=False)
if r_vlan_internal.text.startswith('{"code') and var_coe == "yes": 
	print("Error message: " + r_vlan_internal.text)
	print("Continue...")
elif r_vlan_internal.text.startswith('{"code') and var_coe == "no":
	sys.exit("Script stopped, error message: " + r_vlan_internal.text)
else:
	print("      -> done!")

# VMware NAT
print("    - creating VLAN 'VMware_NAT'")
u_vlan_vmware = "https://" + var_ip_mgmt + "/mgmt/tm/net/vlan"
p_vlan_vmware = "{\n  \"name\": \"VMware_NAT\",\n  \"partition\": \"Common\",\n  \"autoLasthop\": \"default\",\n  \"cmpHash\": \"default\",\n  \"mtu\": \"1500\",\n  \"interfaces\": \n    [ \n        {\n            \"name\":\"" + var_int_vmware + "\",\n            \"tagged\":false\n        }\n    ]\n}"
h_vlan_vmware = {
    'authorization': var_auth_header,
    'content-type': "application/json",
    'cache-control': "no-cache",
    }
r_vlan_vmware = requests.request("POST", u_vlan_vmware, data=p_vlan_vmware, headers=h_vlan_vmware, verify=False)
if r_vlan_vmware.text.startswith('{"code') and var_coe == "yes": 
	print("Error message: " + r_vlan_vmware.text)
	print("Continue...")
elif r_vlan_vmware.text.startswith('{"code') and var_coe == "no":
	sys.exit("Script stopped, error message: " + r_vlan_vmware.text)
else:
	print("      -> done!")

#################################################################################
# create Self-IPs
#################################################################################
print("2.) create Self-IPs")

# External
print("    - creating SelfIP 'External'")
u_self_external = "https://" + var_ip_mgmt + "/mgmt/tm/net/self/"
p_self_external = "{\n   \"name\": \"SelfIP-External\",\n   \"partition\": \"Common\",\n   \"address\": \"" + var_self_external + "/24\",\n   \"floating\": \"disabled\",\n   \"trafficGroup\": \"/Common/traffic-group-local-only\",\n   \"vlan\": \"/Common/External\",\n   \"allowService\": [\n     \"default\"\n   ]\n}"
h_self_external = {
    'content-type': "application/json",
    'authorization': var_auth_header,
    'cache-control': "no-cache",
    }
r_self_external = requests.request("POST", u_self_external, data=p_self_external, headers=h_self_external, verify=False)
if r_self_external.text.startswith('{"code') and var_coe == "yes": 
	print("Error message: " + r_self_external.text)
	print("Continue...")
elif r_self_external.text.startswith('{"code') and var_coe == "no":
	sys.exit("Script stopped, error message: " + r_self_external.text)
else:
	print("      -> done!")

# Internal
print("    - creating SelfIP 'Internal'")
u_self_internal = "https://" + var_ip_mgmt + "/mgmt/tm/net/self/"
p_self_internal = "{\n   \"name\": \"SelfIP-Internal\",\n   \"partition\": \"Common\",\n   \"address\": \"" + var_self_internal + "/24\",\n   \"floating\": \"disabled\",\n   \"trafficGroup\": \"/Common/traffic-group-local-only\",\n   \"vlan\": \"/Common/Internal\",\n   \"allowService\": [\n     \"default\"\n   ]\n}"
h_self_internal = {
    'content-type': "application/json",
    'authorization': var_auth_header,
    'cache-control': "no-cache",
    }
r_self_internal = requests.request("POST", u_self_internal, data=p_self_internal, headers=h_self_internal, verify=False)
if r_self_internal.text.startswith('{"code') and var_coe == "yes": 
	print("Error message: " + r_self_internal.text)
	print("Continue...")
elif r_self_internal.text.startswith('{"code') and var_coe == "no":
	sys.exit("Script stopped, error message: " + r_self_internal.text)
else:
	print("      -> done!")

# VMware NAT
print("    - creating SelfIP 'VMware_NAT'")
u_self_vmware = "https://" + var_ip_mgmt + "/mgmt/tm/net/self/"
p_self_vmware = "{\n   \"name\": \"SelfIP-VMware_NAT\",\n   \"partition\": \"Common\",\n   \"address\": \"" + var_self_vmware + "/24\",\n   \"floating\": \"disabled\",\n   \"trafficGroup\": \"/Common/traffic-group-local-only\",\n   \"vlan\": \"/Common/VMware_NAT\",\n   \"allowService\": [\n     \"default\"\n   ]\n}"
h_self_vmware = {
    'content-type': "application/json",
    'authorization': var_auth_header,
    'cache-control': "no-cache",
    }
r_self_vmware = requests.request("POST", u_self_vmware, data=p_self_vmware, headers=h_self_vmware, verify=False)
if r_self_vmware.text.startswith('{"code') and var_coe == "yes": 
	print("Error message: " + r_self_vmware.text)
	print("Continue...")
elif r_self_vmware.text.startswith('{"code') and var_coe == "no":
	sys.exit("Script stopped, error message: " + r_self_vmware.text)
else:
	print("      -> done!")

#################################################################################
# create Routes
#################################################################################
print("3.) create Routes")

# Default GW
print("    - setting Default Gateway")
u_defaultgw = "https://" + var_ip_mgmt + "/mgmt/tm/net/route"
p_defaultgw = "{\n  \"name\": \"Default_GW\",\n  \"partition\": \"Common\",\n  \"gw\": \"" + var_default_gw + "\",\n  \"mtu\": 0,\n  \"network\": \"0.0.0.0/0\"\n}"
h_defaultgw = {
    'content-type': "application/json",
    'authorization': var_auth_header,
    'cache-control': "no-cache",
    }
r_defaultgw = requests.request("POST", u_defaultgw, data=p_defaultgw, headers=h_defaultgw, verify=False)
if r_defaultgw.text.startswith('{"code') and var_coe == "yes": 
	print("Error message: " + r_defaultgw.text)
	print("Continue...")
elif r_defaultgw.text.startswith('{"code') and var_coe == "no":
	sys.exit("Script stopped, error message: " + r_defaultgw.text)
else:
	print("      -> done!")

#################################################################################
# create UCS Archive
#################################################################################
print("4.) create UCS Archive")

u_create_ucs = "https://" + var_ip_mgmt + "/mgmt/tm/sys/ucs"
p_create_ucs = "{\n    \"command\":\"save\",\n    \"name\":\"backup_" + var_fqdn + "_" + time.strftime("%Y-%m-%d") + ".ucs\"\n}"
h_create_ucs = {
    'content-type': "application/json",
    'authorization': var_auth_header,
    'cache-control': "no-cache",
    }
r_create_ucs = requests.request("POST", u_create_ucs, data=p_create_ucs, headers=h_create_ucs, verify=False)
if r_create_ucs.text.startswith('{"code') and var_coe == "yes": 
	print(r_create_ucs.text)
	print("continue...")
elif r_create_ucs.text.startswith('{"code') and var_coe == "no":
	sys.exit("Script stopped, error message: " + r_create_ucs.text)
else:
	print("      -> done!")

#################################################################################
# Finished
#################################################################################
print("-----------------")
print("-   Finished!   -")
print("-----------------")