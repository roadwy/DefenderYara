
rule MonitoringTool_AndroidOS_AxeSpy_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/AxeSpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,09 00 09 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 61 6e 64 72 6f 69 64 2e 64 6d 70 } //01 00 
		$a_01_1 = {67 65 74 43 61 6c 6c 52 65 63 6f 72 64 44 73 69 64 } //01 00 
		$a_01_2 = {69 73 43 61 6c 6c 52 65 63 6f 72 64 } //01 00 
		$a_01_3 = {2f 2e 75 74 73 6b 2f } //01 00 
		$a_01_4 = {73 70 5f 72 65 73 74 6f 72 65 5f 61 63 74 69 6f 6e 73 } //01 00 
		$a_01_5 = {64 65 6c 65 74 65 46 69 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}