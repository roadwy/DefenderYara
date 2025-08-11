
rule HackTool_MacOS_SuspSoftwareDiscovery_B1{
	meta:
		description = "HackTool:MacOS/SuspSoftwareDiscovery.B1,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {70 00 6c 00 69 00 73 00 74 00 62 00 75 00 64 00 64 00 79 00 [0-80] 2f 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 73 00 2f 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 2e 00 61 00 70 00 70 00 2f 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 73 00 2f 00 69 00 6e 00 66 00 6f 00 2e 00 70 00 6c 00 69 00 73 00 74 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}