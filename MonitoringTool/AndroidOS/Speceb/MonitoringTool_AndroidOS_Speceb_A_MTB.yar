
rule MonitoringTool_AndroidOS_Speceb_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Speceb.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 73 70 65 63 74 6f 72 73 6f 66 74 2f 61 6e 64 72 6f 69 64 2f 6d 6f 6e 69 74 6f 72 } //01 00 
		$a_01_1 = {4d 6f 6e 69 74 6f 72 43 6f 6e 74 72 6f 6c 6c 65 64 54 61 73 6b } //01 00 
		$a_01_2 = {4c 6f 67 63 61 74 4d 6f 6e 69 74 6f 72 } //01 00 
		$a_01_3 = {50 68 6f 6e 65 63 61 6c 6c 4f 62 73 65 72 76 65 72 } //01 00 
		$a_01_4 = {55 73 65 72 53 6d 73 43 61 70 74 75 72 65 } //01 00 
		$a_01_5 = {55 72 6c 4f 62 73 65 72 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}