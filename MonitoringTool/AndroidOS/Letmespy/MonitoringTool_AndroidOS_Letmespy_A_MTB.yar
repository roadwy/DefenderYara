
rule MonitoringTool_AndroidOS_Letmespy_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Letmespy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4d 53 20 4f 55 54 } //01 00 
		$a_01_1 = {69 73 43 6f 6c 6c 65 63 74 50 68 6f 6e 65 } //01 00 
		$a_01_2 = {6c 6f 61 64 50 68 6f 6e 65 73 44 6f } //01 00 
		$a_01_3 = {63 68 65 63 6b 43 6f 6c 6c 65 63 74 50 68 6f 6e 65 54 61 73 6b } //01 00 
		$a_01_4 = {6c 6f 67 43 61 6c 6c 4c 6f 67 } //01 00 
		$a_01_5 = {70 6c 2e 6c 69 64 77 69 6e 2e 6c 65 74 6d 65 73 70 79 } //01 00 
		$a_01_6 = {69 63 6f 6e 48 69 64 65 } //00 00 
	condition:
		any of ($a_*)
 
}