
rule MonitoringTool_AndroidOS_Pholoc_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Pholoc.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {77 65 62 2e 6d 65 2e 63 6f 6d } //01 00 
		$a_00_1 = {72 76 6f 61 6e 64 65 76 2f 50 68 6f 6e 65 4c 6f 63 61 74 6f 72 2f 50 72 6f 5f 76 65 72 73 69 6f 6e 2e 68 74 6d 6c } //01 00 
		$a_00_2 = {73 68 6f 72 74 4c 6f 67 20 6f 75 74 67 6f 69 6e 67 } //01 00 
		$a_00_3 = {4c 6f 63 6b 20 64 65 76 69 63 65 20 6f 6e 20 73 63 72 65 65 6e } //01 00 
		$a_00_4 = {73 65 6e 64 20 65 6d 61 69 6c 20 66 6d 20 4c 6f 63 61 74 69 6f 6e } //01 00 
		$a_00_5 = {74 65 78 74 5f 53 69 6d 43 68 65 63 6b 5f 6c 6f 63 6b 65 64 } //00 00 
	condition:
		any of ($a_*)
 
}