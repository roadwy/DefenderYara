
rule HackTool_MacOS_SuspPolicyDiscovery_A1{
	meta:
		description = "HackTool:MacOS/SuspPolicyDiscovery.A1,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_00_0 = {70 00 77 00 70 00 6f 00 6c 00 69 00 63 00 79 00 20 00 67 00 65 00 74 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 70 00 6f 00 6c 00 69 00 63 00 69 00 65 00 73 00 } //10 pwpolicy getaccountpolicies
	condition:
		((#a_00_0  & 1)*10) >=10
 
}