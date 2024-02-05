
rule MonitoringTool_AndroidOS_SAgnt_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/SAgnt.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 72 61 63 6b 69 6e 67 5f 73 74 61 72 74 5f 74 69 6d 65 } //01 00 
		$a_01_1 = {53 4d 53 5f 43 4f 4f 52 44 49 4e 41 54 45 53 5f 46 4f 55 4e 44 } //01 00 
		$a_00_2 = {69 6e 74 65 72 70 72 65 74 65 53 4d 53 } //01 00 
		$a_00_3 = {64 65 2f 74 72 61 63 6b 69 6e 67 2f 74 72 61 63 6b 2f 4c 6f 63 61 74 69 6f 6e 54 72 61 63 6b 65 72 } //01 00 
		$a_00_4 = {70 68 6f 6e 65 4e 75 6d 62 65 72 54 6f 54 72 61 63 6b } //00 00 
	condition:
		any of ($a_*)
 
}