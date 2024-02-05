
rule MonitoringTool_AndroidOS_OneSpy_C_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/OneSpy.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 55 70 6c 6f 61 64 49 6e 74 65 6e 74 53 65 72 76 69 63 65 } //01 00 
		$a_01_1 = {44 69 73 61 62 6c 65 41 70 70 73 49 6e 74 65 6e 74 53 65 72 76 69 63 65 } //01 00 
		$a_01_2 = {2f 73 62 69 6e 2f 2e 6d 61 67 69 73 6b 2f 69 6d 67 2f 70 68 6f 6e 65 73 70 79 2d 73 74 75 62 } //01 00 
		$a_01_3 = {53 63 72 65 65 6e 73 68 6f 74 57 69 74 68 52 6f 6f 74 49 6e 74 65 6e 74 53 65 72 76 69 63 65 } //01 00 
		$a_01_4 = {53 75 72 72 6f 75 6e 64 52 65 63 6f 72 64 65 72 53 65 72 76 69 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}