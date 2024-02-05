
rule MonitoringTool_AndroidOS_SAgnt_E_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/SAgnt.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,09 00 09 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 74 61 63 74 49 6e 66 6f 41 63 74 69 76 69 74 79 } //01 00 
		$a_01_1 = {55 70 6c 6f 61 64 4c 6f 67 41 63 74 69 76 69 74 79 } //05 00 
		$a_01_2 = {4c 63 6f 6d 2f 68 65 63 6f 6d 2f 6d 67 6d } //01 00 
		$a_01_3 = {44 65 76 69 63 65 4d 6f 62 69 6c 65 4e 65 74 44 42 4d 49 6e 66 6f } //01 00 
		$a_01_4 = {68 65 63 6f 6d 2f 70 69 63 74 6d 70 2f } //01 00 
		$a_01_5 = {6b 69 63 6b 65 64 4f 75 74 4d 73 67 } //01 00 
		$a_01_6 = {63 6f 6e 74 61 63 74 43 68 61 74 53 65 61 72 63 68 48 69 73 74 6f 72 79 } //00 00 
	condition:
		any of ($a_*)
 
}