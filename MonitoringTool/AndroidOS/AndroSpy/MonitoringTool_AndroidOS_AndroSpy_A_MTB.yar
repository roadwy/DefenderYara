
rule MonitoringTool_AndroidOS_AndroSpy_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/AndroSpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 63 6f 72 64 47 70 73 } //01 00 
		$a_01_1 = {67 70 73 74 72 61 63 6b 65 72 5f 42 72 6f 61 64 63 61 73 74 } //05 00 
		$a_01_2 = {61 70 6b 2f 67 70 73 74 72 61 63 6b 65 72 2f 41 75 74 6f 44 65 6c 65 74 65 } //05 00 
		$a_01_3 = {4c 63 6f 6d 2f 61 73 2f 67 70 73 74 72 61 63 6b 65 72 } //01 00 
		$a_01_4 = {61 2d 73 70 79 } //01 00 
		$a_01_5 = {68 69 64 65 5f 6e 6f 74 69 66 69 63 61 74 69 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}