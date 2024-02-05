
rule MonitoringTool_AndroidOS_FreeSpy_DS_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/FreeSpy.DS!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {42 72 6f 77 73 65 72 48 69 73 74 6f 72 79 43 6f 6c 6c 65 63 74 6f 72 } //01 00 
		$a_00_1 = {4b 65 79 6c 6f 67 53 74 61 74 65 4d 6f 6e 69 74 6f 72 } //01 00 
		$a_00_2 = {43 6f 6e 74 61 63 74 4f 62 73 65 72 76 65 72 } //01 00 
		$a_00_3 = {43 61 6c 6c 4d 6f 6e 69 74 6f 72 } //01 00 
		$a_00_4 = {53 6d 73 4d 6f 6e 69 74 6f 72 } //01 00 
		$a_00_5 = {46 61 63 65 62 6f 6f 6b 4d 65 73 73 61 67 65 45 78 74 72 61 63 74 6f 72 } //00 00 
	condition:
		any of ($a_*)
 
}