
rule MonitoringTool_AndroidOS_Anlost_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Anlost.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {67 65 74 74 69 6e 67 20 53 6d 73 20 64 65 74 61 69 6c 73 } //01 00 
		$a_00_1 = {53 4d 53 5f 52 45 41 44 5f 43 4f 4c 55 4d 4e } //01 00 
		$a_00_2 = {6c 6f 73 74 61 70 70 } //01 00 
		$a_00_3 = {57 69 70 65 20 70 68 6f 6e 65 } //01 00 
		$a_00_4 = {53 4d 53 20 47 50 53 20 69 6e 69 74 69 61 74 65 64 } //01 00 
		$a_00_5 = {61 6e 64 72 6f 69 64 6c 6f 73 74 20 77 69 70 65 } //00 00 
		$a_00_6 = {5d 04 00 00 } //12 98 
	condition:
		any of ($a_*)
 
}