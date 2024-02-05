
rule MonitoringTool_AndroidOS_Nasp_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Nasp.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 61 6e 53 70 79 } //01 00 
		$a_00_1 = {53 41 53 43 61 70 74 75 72 65 54 61 73 6b 20 } //01 00 
		$a_00_2 = {4b 65 79 4c 6f 67 41 70 70 6c 69 63 61 74 69 6f 6e } //01 00 
		$a_00_3 = {43 6c 69 70 62 6f 61 72 64 69 6e 66 6f } //01 00 
		$a_00_4 = {68 69 73 74 6f 72 79 43 61 6c 6c 4c 6f 67 } //01 00 
		$a_00_5 = {63 6f 6d 2e 70 61 6e 73 70 79 2e 61 6e 64 72 6f 69 64 2e 6b 65 79 6c 6f 67 6c 69 62 } //01 00 
		$a_00_6 = {52 65 6d 6f 76 65 49 63 6f 6e 41 63 74 69 76 69 74 79 } //00 00 
	condition:
		any of ($a_*)
 
}