
rule MonitoringTool_AndroidOS_Cerberus_F_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Cerberus.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 72 65 76 65 6e 74 75 73 62 64 65 62 75 67 } //01 00 
		$a_00_1 = {47 45 54 5f 41 50 50 5f 4c 49 53 54 } //01 00 
		$a_00_2 = {53 43 52 45 45 4e 52 45 43 4f 52 44 } //01 00 
		$a_00_3 = {63 65 72 62 65 72 75 73 } //01 00 
		$a_00_4 = {53 4d 53 5f 53 45 4e 54 } //01 00 
		$a_00_5 = {57 49 50 45 53 44 } //00 00 
	condition:
		any of ($a_*)
 
}