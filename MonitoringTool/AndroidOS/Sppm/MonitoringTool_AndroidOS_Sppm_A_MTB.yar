
rule MonitoringTool_AndroidOS_Sppm_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Sppm.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,09 00 09 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 70 70 6d 57 61 74 63 68 52 65 63 65 69 76 65 72 } //01 00 
		$a_00_1 = {41 6c 6c 6f 77 49 6e 73 74 61 6c 6c 69 6e 67 55 6e 6b 6e 6f 77 6e 41 70 70 73 41 63 74 69 76 69 74 79 } //01 00 
		$a_00_2 = {69 73 41 70 70 4d 6f 6e 69 74 6f 72 69 6e 67 } //05 00 
		$a_00_3 = {6a 70 2e 63 6f 2e 61 78 73 65 65 64 2e 73 70 70 6d 5f 73 65 74 75 70 } //01 00 
		$a_00_4 = {73 70 70 6d 63 61 6c 6c 63 74 72 6c } //01 00 
		$a_00_5 = {57 49 50 45 43 41 4c 4c 4e 4f } //00 00 
	condition:
		any of ($a_*)
 
}