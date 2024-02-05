
rule MonitoringTool_AndroidOS_Spymob_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Spymob.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 69 64 64 65 6e 41 70 70 73 43 6f 6e 66 69 67 41 63 74 69 76 69 74 79 } //01 00 
		$a_01_1 = {54 72 61 63 6b 50 68 6f 6e 65 } //01 00 
		$a_01_2 = {50 68 6f 6e 65 57 61 73 4c 69 6e 6b 65 64 } //01 00 
		$a_01_3 = {43 61 6c 6c 52 65 63 65 69 76 65 72 } //01 00 
		$a_01_4 = {64 65 6c 69 76 65 72 53 65 6c 66 4e 6f 74 69 66 69 63 61 74 69 6f 6e 73 } //00 00 
	condition:
		any of ($a_*)
 
}