
rule MonitoringTool_AndroidOS_ScreenLog_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/ScreenLog.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 77 75 6c 74 72 61 2f 61 70 70 } //01 00  Lcom/wultra/app
		$a_00_1 = {52 65 63 6f 72 64 69 6e 67 4f 62 73 65 72 76 61 62 6c 65 } //01 00  RecordingObservable
		$a_00_2 = {73 74 6f 72 65 4c 6f 67 45 6e 74 72 79 } //01 00  storeLogEntry
		$a_00_3 = {73 63 72 65 65 6e 6c 6f 67 67 65 72 } //00 00  screenlogger
	condition:
		any of ($a_*)
 
}