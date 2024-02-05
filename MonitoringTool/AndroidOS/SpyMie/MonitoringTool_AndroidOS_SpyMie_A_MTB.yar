
rule MonitoringTool_AndroidOS_SpyMie_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/SpyMie.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 73 70 79 6c 6f 67 67 65 72 2f 61 70 70 2f 73 70 79 6c 6f 67 67 65 72 } //01 00 
		$a_00_1 = {2f 75 74 69 6c 73 2f 4b 65 79 4c 6f 67 67 65 72 } //01 00 
		$a_00_2 = {2f 75 74 69 6c 73 2f 53 65 6e 64 4d 61 69 6c } //01 00 
		$a_00_3 = {73 74 6f 72 65 52 65 63 6f 72 64 } //01 00 
		$a_00_4 = {7c 28 54 45 58 54 29 7c } //00 00 
		$a_00_5 = {5d 04 00 00 } //49 e9 
	condition:
		any of ($a_*)
 
}