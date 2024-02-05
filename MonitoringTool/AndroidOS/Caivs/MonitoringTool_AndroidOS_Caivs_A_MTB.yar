
rule MonitoringTool_AndroidOS_Caivs_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Caivs.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 63 61 69 76 73 2f 61 70 70 2f 43 61 6c 6c 4c 6f 67 73 4f 62 73 65 72 76 65 72 } //01 00 
		$a_00_1 = {73 74 61 72 74 53 65 6e 64 53 6d 73 53 65 72 76 65 72 } //01 00 
		$a_00_2 = {72 65 67 69 73 74 65 72 53 6d 73 52 65 63 65 69 76 65 72 } //01 00 
		$a_00_3 = {64 65 6c 61 79 52 65 6d 6f 76 65 53 65 6c 66 } //01 00 
		$a_00_4 = {67 65 74 53 65 6e 64 43 6f 75 6e 74 } //01 00 
		$a_00_5 = {77 6f 6c 66 74 65 6c 5f 63 61 69 76 73 2f 6c 6f 67 73 2e 64 61 74 61 } //00 00 
	condition:
		any of ($a_*)
 
}