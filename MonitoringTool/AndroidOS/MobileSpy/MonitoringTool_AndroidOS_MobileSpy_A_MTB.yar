
rule MonitoringTool_AndroidOS_MobileSpy_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/MobileSpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {52 65 63 6f 72 64 43 61 6c 6c 6c 6f 67 73 } //01 00 
		$a_00_1 = {4d 6f 62 69 6c 65 53 70 79 } //01 00 
		$a_00_2 = {67 70 73 6c 6f 67 2e 70 68 70 } //01 00 
		$a_00_3 = {6f 75 74 67 6f 69 6e 67 43 61 6c 6c 52 65 63 6f 72 64 } //01 00 
		$a_01_4 = {57 49 50 45 5f 4c 4f 47 } //00 00 
	condition:
		any of ($a_*)
 
}