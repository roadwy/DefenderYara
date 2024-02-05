
rule MonitoringTool_AndroidOS_BosSpy_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/BosSpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 44 61 74 61 4f 66 53 4d 53 54 6f 57 65 62 73 69 74 65 } //01 00 
		$a_01_1 = {73 70 79 43 61 6c 6c 4e 75 6d 62 65 72 } //01 00 
		$a_01_2 = {53 70 79 6f 6f 53 65 72 76 69 63 65 } //01 00 
		$a_01_3 = {63 6c 69 70 62 6f 61 72 64 42 79 70 61 73 73 } //01 00 
		$a_01_4 = {4b 65 79 6c 6f 67 53 65 72 76 69 63 65 } //01 00 
		$a_01_5 = {65 74 4d 6f 6e 69 74 6f 72 69 6e 67 50 68 6f 6e 65 } //00 00 
	condition:
		any of ($a_*)
 
}