
rule MonitoringTool_AndroidOS_KidLogger_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/KidLogger.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {6c 6f 67 43 61 6c 6c 73 } //01 00  logCalls
		$a_00_1 = {67 65 74 4b 65 79 73 74 72 6f 6b 65 } //01 00  getKeystroke
		$a_00_2 = {75 70 6c 6f 61 64 4b 65 79 } //01 00  uploadKey
		$a_00_3 = {4b 69 64 4c 6f 63 4c 69 73 74 65 6e 65 72 } //01 00  KidLocListener
		$a_00_4 = {6e 65 74 2e 6b 69 64 6c 6f 67 67 65 72 } //01 00  net.kidlogger
		$a_00_5 = {6c 6f 67 67 65 72 6b 65 79 62 6f 61 72 64 } //00 00  loggerkeyboard
		$a_00_6 = {5d 04 00 00 } //e6 90 
	condition:
		any of ($a_*)
 
}