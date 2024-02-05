
rule MonitoringTool_AndroidOS_Anlost_C_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Anlost.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 6d 73 20 67 70 73 20 69 6e 69 74 69 61 74 65 64 } //01 00 
		$a_00_1 = {63 6f 6d 2f 61 6e 64 72 6f 69 64 6c 6f 73 74 2f 6c 6f 73 74 61 70 70 } //01 00 
		$a_00_2 = {77 69 70 65 64 61 74 61 } //01 00 
		$a_00_3 = {69 73 61 64 6d 69 6e 61 63 74 69 76 65 } //01 00 
		$a_00_4 = {6c 6f 63 6b 4e 6f 77 } //00 00 
	condition:
		any of ($a_*)
 
}