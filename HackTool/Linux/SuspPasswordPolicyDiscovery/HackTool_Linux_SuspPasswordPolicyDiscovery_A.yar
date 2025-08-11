
rule HackTool_Linux_SuspPasswordPolicyDiscovery_A{
	meta:
		description = "HackTool:Linux/SuspPasswordPolicyDiscovery.A,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_00_0 = {63 00 68 00 61 00 67 00 65 00 20 00 2d 00 6c 00 } //10 chage -l
	condition:
		((#a_00_0  & 1)*10) >=10
 
}