
rule MonitoringTool_AndroidOS_ManaMon_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/ManaMon.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 6d 73 49 6e 66 6f } //01 00 
		$a_00_1 = {4d 53 47 5f 4f 55 54 42 4f 58 43 4f 4e 54 45 4e 54 } //01 00 
		$a_00_2 = {55 50 4c 4f 41 44 5f 53 45 52 56 45 52 } //01 00 
		$a_00_3 = {63 61 6c 6c 52 65 63 6f 72 64 49 6e 66 6f } //01 00 
		$a_00_4 = {75 70 6c 6f 61 64 52 65 63 6f 64 65 72 } //01 00 
		$a_00_5 = {6d 61 6e 61 67 65 72 69 5f 63 61 6c 6c 5f 73 65 6e 64 } //00 00 
	condition:
		any of ($a_*)
 
}