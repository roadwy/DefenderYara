
rule MonitoringTool_AndroidOS_TalkLog_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/TalkLog.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 44 6f 77 6e 6c 6f 61 64 2f 74 61 6c 6b 6c 6f 67 2e 61 70 6b } //01 00  /Download/talklog.apk
		$a_00_1 = {74 63 68 73 72 76 63 65 2e 63 6f 6d } //01 00  tchsrvce.com
		$a_00_2 = {2f 4f 62 73 65 72 76 65 72 53 65 72 76 69 63 65 2f 43 68 72 6f 6d 65 4f 62 73 65 72 76 65 72 53 65 72 76 69 63 65 } //01 00  /ObserverService/ChromeObserverService
		$a_00_3 = {49 6e 43 6f 6d 69 6e 67 53 6d 73 42 72 6f 61 64 52 65 63 65 69 76 65 72 } //01 00  InComingSmsBroadReceiver
		$a_00_4 = {63 75 72 72 65 6e 74 5f 6d 6f 6e 69 74 6f 72 69 6e 67 } //01 00  current_monitoring
		$a_00_5 = {68 69 64 64 65 6e 5f 69 63 6f 6e } //00 00  hidden_icon
	condition:
		any of ($a_*)
 
}