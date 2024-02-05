
rule MonitoringTool_AndroidOS_Secneo_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Secneo.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {57 78 4d 6f 6e 69 74 6f 72 41 70 70 6c 69 63 61 74 69 6f 6e } //01 00 
		$a_00_1 = {68 64 2e 66 69 73 68 2e 57 78 4d 6f 6e 69 74 6f 72 } //01 00 
		$a_00_2 = {63 6f 6d 2e 73 65 63 6e 65 6f 2e 74 6d 70 } //01 00 
		$a_00_3 = {53 65 63 53 68 65 6c 6c } //01 00 
		$a_00_4 = {4c 63 6f 6d 2f 73 65 63 73 68 65 6c 6c 2f 73 65 63 44 61 74 61 2f 46 69 6c 65 73 46 69 6c 65 4f 62 73 65 72 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}