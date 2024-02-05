
rule MonitoringTool_AndroidOS_ASpy_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/ASpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 61 73 2e 75 72 6c 6c 6f 67 67 65 72 } //01 00 
		$a_00_1 = {44 61 74 61 42 61 73 65 2e 44 65 6c 65 74 65 41 6c 6c } //01 00 
		$a_00_2 = {50 6f 77 65 72 4f 70 74 43 6c 69 63 6b } //01 00 
		$a_00_3 = {4c 61 70 6b 2f 75 72 6c 6c 6f 67 67 65 72 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //01 00 
		$a_00_4 = {41 75 74 6f 44 65 6c 65 74 65 } //01 00 
		$a_00_5 = {47 65 74 4c 61 73 74 52 65 63 6f 72 64 } //00 00 
		$a_00_6 = {5d 04 00 00 } //8c fe 
	condition:
		any of ($a_*)
 
}