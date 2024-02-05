
rule MonitoringTool_AndroidOS_TalkLog_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/TalkLog.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 75 72 72 65 6e 74 5f 6d 6f 6e 69 74 6f 72 69 6e 67 } //01 00 
		$a_00_1 = {74 74 70 73 3a 2f 2f 74 63 68 73 72 76 63 65 2e 63 6f 6d 2f 63 6f 6e 32 33 33 2e 70 68 70 } //01 00 
		$a_00_2 = {4f 62 73 65 72 76 65 72 4f 75 74 63 6f 6d 69 6e 67 53 4d 53 } //01 00 
		$a_00_3 = {70 6f 73 74 2f 68 6f 6f 6b 2e 70 68 70 } //01 00 
		$a_00_4 = {70 6f 73 74 2f 66 69 6c 65 2e 70 68 70 } //01 00 
		$a_00_5 = {54 61 6c 6b 6c 6f 67 20 54 6f 6f 6c 73 } //00 00 
	condition:
		any of ($a_*)
 
}