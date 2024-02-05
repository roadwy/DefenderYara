
rule MonitoringTool_AndroidOS_Etooe_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Etooe.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 77 61 6e 67 6c 69 6e 67 2e 72 65 6d 6f 74 65 70 68 6f 6e 65 } //01 00 
		$a_01_1 = {4c 6f 63 61 74 69 6f 6e 4d 61 70 2e 70 68 70 } //01 00 
		$a_01_2 = {79 6b 7a 2e 65 32 65 79 65 2e 63 6f 6d 2f 63 6c 6f 75 64 63 74 72 6c } //01 00 
		$a_01_3 = {53 6d 73 43 6f 6d 65 52 65 63 65 69 76 65 72 } //01 00 
		$a_01_4 = {4d 6f 62 69 6c 65 43 61 6d 65 72 61 53 65 72 76 69 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}