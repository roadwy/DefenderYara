
rule MonitoringTool_AndroidOS_LiveTrack_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/LiveTrack.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 6e 73 74 61 6c 6c 65 64 61 70 70 73 6c 6f 67 } //01 00 
		$a_01_1 = {62 61 63 6b 75 70 5f 63 61 6c 6c 5f 6c 6f 67 } //01 00 
		$a_01_2 = {75 70 6c 6f 61 64 20 42 72 6f 77 73 65 72 20 48 69 73 74 } //01 00 
		$a_01_3 = {69 73 5f 75 70 6c 6f 61 64 5f 73 6d 73 5f 6c 6f 67 } //01 00 
		$a_01_4 = {75 70 6c 6f 61 64 20 43 6f 6e 74 61 63 74 73 } //01 00 
		$a_00_5 = {63 6f 6d 2e 64 65 76 69 63 65 2e 73 79 73 74 65 6d } //00 00 
	condition:
		any of ($a_*)
 
}