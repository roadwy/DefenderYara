
rule MonitoringTool_AndroidOS_MissingDroid_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/MissingDroid.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 6d 73 4d 73 67 52 65 63 } //01 00 
		$a_00_1 = {73 65 6e 74 53 6d 73 4c 6f 63 61 74 69 6f 6e 46 6f 75 6e 64 } //01 00 
		$a_00_2 = {46 69 6e 64 4d 79 44 72 6f 69 64 } //01 00 
		$a_00_3 = {53 6d 73 53 74 6f 6c 65 6e 4d 73 67 } //01 00 
		$a_00_4 = {68 69 64 65 41 70 70 } //01 00 
		$a_00_5 = {66 72 69 65 6e 64 73 57 69 70 65 } //00 00 
		$a_00_6 = {5d 04 00 00 } //5a ba 
	condition:
		any of ($a_*)
 
}