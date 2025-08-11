
rule HackTool_MacOS_SuspSharedResourceDiscovery_A1{
	meta:
		description = "HackTool:MacOS/SuspSharedResourceDiscovery.A1,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_00_0 = {73 00 6d 00 62 00 75 00 74 00 69 00 6c 00 20 00 76 00 69 00 65 00 77 00 20 00 2d 00 67 00 20 00 2f 00 2f 00 } //10 smbutil view -g //
	condition:
		((#a_00_0  & 1)*10) >=10
 
}