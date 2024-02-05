
rule MonitoringTool_AndroidOS_SMSBox_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/SMSBox.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 6d 73 42 6f 78 41 63 74 69 76 69 74 79 } //01 00 
		$a_00_1 = {73 6d 61 72 74 67 70 73 77 6f 72 6c 64 2e 63 6f 6d 2f 53 6d 73 42 6f 78 } //01 00 
		$a_01_2 = {53 4d 53 5f 41 55 54 4f 53 54 41 52 54 } //01 00 
		$a_00_3 = {73 6d 73 20 61 6e 64 20 63 61 6c 6c 73 20 68 69 73 74 6f 72 79 20 73 61 76 65 64 20 6f 6e 20 74 68 65 20 77 65 62 } //01 00 
		$a_00_4 = {73 65 6e 64 43 61 6c 6c 49 6e 66 6f } //00 00 
	condition:
		any of ($a_*)
 
}