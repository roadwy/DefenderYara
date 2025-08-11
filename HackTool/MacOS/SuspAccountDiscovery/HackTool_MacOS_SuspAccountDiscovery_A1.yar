
rule HackTool_MacOS_SuspAccountDiscovery_A1{
	meta:
		description = "HackTool:MacOS/SuspAccountDiscovery.A1,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_00_0 = {63 00 61 00 74 00 20 00 2f 00 65 00 74 00 63 00 2f 00 70 00 61 00 73 00 73 00 77 00 64 00 } //10 cat /etc/passwd
	condition:
		((#a_00_0  & 1)*10) >=10
 
}