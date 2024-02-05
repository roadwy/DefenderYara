
rule MonitoringTool_AndroidOS_OwnSpy_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/OwnSpy.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 72 61 63 6b 69 6e 67 72 61 74 65 } //01 00 
		$a_00_1 = {73 6d 73 5f 63 6f 6e 6e 65 63 74 } //01 00 
		$a_00_2 = {70 72 65 76 65 6e 74 5f 75 6e 69 6e 73 74 61 6c 6c } //01 00 
		$a_00_3 = {4f 57 4e 53 50 59 } //01 00 
		$a_00_4 = {61 70 70 73 54 6f 72 65 63 6f 72 64 } //01 00 
		$a_00_5 = {4b 65 79 4c 6f 67 67 65 72 } //01 00 
		$a_00_6 = {43 68 72 6f 6d 65 55 52 4c 4d 6f 6e 69 74 6f 72 } //01 00 
		$a_00_7 = {53 63 72 65 65 6e 52 65 63 6f 72 64 53 65 72 76 69 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}