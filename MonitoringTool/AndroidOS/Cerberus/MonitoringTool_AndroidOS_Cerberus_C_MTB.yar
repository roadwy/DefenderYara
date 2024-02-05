
rule MonitoringTool_AndroidOS_Cerberus_C_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Cerberus.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 65 72 62 65 72 75 73 61 70 70 2e 63 6f 6d 2f 61 70 69 2f 67 65 74 64 65 76 69 63 65 73 2e 70 68 70 } //01 00 
		$a_01_1 = {53 45 4e 44 5f 53 4d 53 5f 52 45 53 55 4c 54 } //01 00 
		$a_01_2 = {63 65 72 62 65 72 75 73 } //01 00 
		$a_01_3 = {63 6f 6d 2f 6c 73 64 72 6f 69 64 2f 63 65 72 62 65 72 75 73 } //01 00 
		$a_01_4 = {67 65 74 64 65 76 69 63 65 73 74 61 74 75 73 2e 70 68 70 } //00 00 
	condition:
		any of ($a_*)
 
}