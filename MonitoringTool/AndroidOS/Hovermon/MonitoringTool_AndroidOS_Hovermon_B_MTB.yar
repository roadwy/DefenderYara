
rule MonitoringTool_AndroidOS_Hovermon_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Hovermon.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 49 50 4b 4f 4d 4f 4e 49 54 4f 52 } //01 00 
		$a_00_1 = {4d 6f 6e 69 74 6f 72 69 6e 67 20 65 6e 61 62 6c 65 64 } //01 00 
		$a_00_2 = {61 2e 68 77 73 2e 69 63 75 } //01 00 
		$a_01_3 = {43 48 41 54 52 45 43 } //01 00 
		$a_01_4 = {53 4d 53 53 43 52 45 45 4e 53 48 4f 54 53 } //01 00 
		$a_01_5 = {57 45 42 53 43 52 45 45 4e 53 48 4f 54 53 } //01 00 
		$a_00_6 = {68 69 64 65 5f 6c 61 75 6e 63 68 65 72 } //00 00 
		$a_00_7 = {5d 04 00 00 } //3f 13 
	condition:
		any of ($a_*)
 
}