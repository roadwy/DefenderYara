
rule MonitoringTool_AndroidOS_KidLogger_D_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/KidLogger.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {6b 69 64 6c 6f 67 67 65 72 2e 6e 65 74 } //01 00  kidlogger.net
		$a_00_1 = {6c 6f 67 43 61 6c 6c 73 } //01 00  logCalls
		$a_00_2 = {67 65 74 4b 65 79 73 74 72 6f 6b 65 } //01 00  getKeystroke
		$a_00_3 = {6c 6f 67 43 6c 69 70 62 6f 61 72 64 } //01 00  logClipboard
		$a_00_4 = {75 70 6c 6f 61 64 4b 65 79 } //01 00  uploadKey
		$a_00_5 = {4b 69 64 4c 6f 63 4c 69 73 74 65 6e 65 72 } //00 00  KidLocListener
	condition:
		any of ($a_*)
 
}