
rule MonitoringTool_AndroidOS_Aspy_F_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Aspy.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 61 73 2e 6b 65 79 6c 6f 67 67 65 72 } //01 00 
		$a_01_1 = {6b 65 79 6c 6f 67 67 65 72 5f 42 72 6f 61 64 63 61 73 74 } //01 00 
		$a_01_2 = {61 63 74 69 76 61 74 65 5f 61 63 63 5f 6d 65 73 73 61 67 65 } //01 00 
		$a_01_3 = {61 73 6b 5f 64 65 6c 65 74 65 5f 61 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}