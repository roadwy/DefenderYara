
rule MonitoringTool_AndroidOS_Aspy_G_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Aspy.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 61 73 2e 75 72 6c 6c 6f 67 67 65 72 } //01 00 
		$a_01_1 = {75 72 6c 6c 6f 67 67 65 72 5f 42 72 6f 61 64 63 61 73 74 } //01 00 
		$a_01_2 = {61 73 6b 5f 64 65 6c 65 74 65 5f 61 6c 6c } //01 00 
		$a_01_3 = {61 70 6b 2e 75 72 6c 6c 6f 67 67 65 72 2e 41 70 70 } //01 00 
		$a_01_4 = {61 63 74 69 76 61 74 65 5f 61 63 63 5f 6d 65 73 73 61 67 65 } //00 00 
	condition:
		any of ($a_*)
 
}