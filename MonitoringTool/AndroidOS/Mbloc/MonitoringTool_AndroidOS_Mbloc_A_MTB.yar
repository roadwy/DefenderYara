
rule MonitoringTool_AndroidOS_Mbloc_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Mbloc.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 6c 69 66 65 70 72 6f 74 6f 2f 72 6d 74 } //05 00 
		$a_01_1 = {72 75 2e 6c 69 66 65 70 72 6f 74 6f 2e 72 6d 74 } //01 00 
		$a_01_2 = {41 6e 73 77 65 72 50 6f 73 74 46 69 6c 65 } //01 00 
		$a_01_3 = {42 52 4f 41 44 5f 49 44 43 41 4c 4c } //01 00 
		$a_01_4 = {4e 6f 74 69 66 69 63 61 74 69 6f 6e 4d 61 6e 61 67 65 72 4d 6f 6e } //01 00 
		$a_01_5 = {42 52 4f 41 44 43 41 53 54 5f 45 4e 44 5f 53 59 4e 43 5f 41 4c 4c } //00 00 
	condition:
		any of ($a_*)
 
}