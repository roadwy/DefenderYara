
rule MonitoringTool_AndroidOS_MSpy_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/MSpy.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {61 70 70 68 65 6c 70 65 72 2e 69 64 65 76 73 2e 63 6f } //01 00 
		$a_00_1 = {49 6e 73 74 61 67 72 61 6d 47 72 61 62 62 65 72 } //01 00 
		$a_00_2 = {4b 65 79 4c 6f 67 67 65 72 53 65 6e 73 6f 72 43 6f 6e 74 72 6f 6c 6c 65 72 } //01 00 
		$a_00_3 = {6d 73 70 79 5f 6b 65 79 62 6f 61 72 64 } //01 00 
		$a_00_4 = {57 68 61 74 73 41 70 70 53 65 6e 73 6f 72 } //00 00 
	condition:
		any of ($a_*)
 
}