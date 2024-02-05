
rule MonitoringTool_AndroidOS_Prospero_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Prospero.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 73 65 6e 64 43 6f 6e 74 61 63 74 73 } //01 00 
		$a_01_1 = {49 6e 63 6f 6d 69 6e 67 53 4d 53 42 61 63 6b 75 70 } //01 00 
		$a_01_2 = {4b 69 6c 6c 53 4d 53 42 79 49 44 } //01 00 
		$a_01_3 = {70 72 6f 73 70 65 72 6f 2e 70 72 6f 2f 67 70 73 2e 70 68 70 } //01 00 
		$a_01_4 = {4b 69 6c 6c 43 6f 6e 74 61 63 74 73 } //01 00 
		$a_01_5 = {50 72 6f 53 70 65 72 6f 53 65 72 76 69 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}