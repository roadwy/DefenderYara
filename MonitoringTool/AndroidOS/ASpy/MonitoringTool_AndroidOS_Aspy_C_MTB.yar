
rule MonitoringTool_AndroidOS_Aspy_C_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Aspy.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 2d 73 70 79 2e 63 6f 6d 2f 3f 61 70 70 3d 63 6f 6d 2e 61 73 2e 6b 65 79 6c 6f 67 67 65 72 } //01 00 
		$a_01_1 = {63 6f 6d 2e 61 73 2e 6b 65 79 6c 6f 67 67 65 72 } //01 00 
		$a_01_2 = {6b 65 79 6c 6f 67 67 65 72 5f 42 72 6f 61 64 63 61 73 74 } //01 00 
		$a_01_3 = {41 63 63 53 76 63 } //00 00 
	condition:
		any of ($a_*)
 
}