
rule MonitoringTool_AndroidOS_PhoneLeash_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/PhoneLeash.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 4f 47 47 45 52 5f 52 4f 4f 54 } //01 00 
		$a_01_1 = {70 68 6f 6e 65 6c 65 61 73 68 2e 6c 6f 67 } //01 00 
		$a_01_2 = {73 74 61 72 74 4d 61 69 6e 50 68 6f 6e 65 4c 65 61 73 68 53 65 72 76 69 63 65 } //01 00 
		$a_01_3 = {6c 61 73 74 4f 75 74 67 6f 69 6e 67 53 6d 73 54 69 6d 65 } //01 00 
		$a_01_4 = {63 6f 6d 2e 67 65 61 72 61 6e 64 72 6f 69 64 2e 70 68 6f 6e 65 6c 65 61 73 68 66 72 65 65 } //00 00 
	condition:
		any of ($a_*)
 
}