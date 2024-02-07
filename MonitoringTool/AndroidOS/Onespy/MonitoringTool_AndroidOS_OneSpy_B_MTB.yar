
rule MonitoringTool_AndroidOS_OneSpy_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/OneSpy.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 62 69 6e 2f 2e 6d 61 67 69 73 6b 2f 69 6d 67 2f 70 68 6f 6e 65 73 70 79 2d 73 74 75 62 } //01 00  sbin/.magisk/img/phonespy-stub
		$a_00_1 = {73 65 6e 64 2e 6f 6e 65 73 70 79 2e 63 6f 6d } //01 00  send.onespy.com
		$a_00_2 = {66 65 61 74 75 72 65 5f 63 61 6c 6c 5f 72 65 63 6f 72 64 69 6e 67 73 } //01 00  feature_call_recordings
		$a_00_3 = {6b 65 79 6c 6f 67 67 65 72 5f 6c 61 73 74 5f 74 69 6d 65 } //01 00  keylogger_last_time
		$a_00_4 = {63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 73 79 73 74 65 6d 2f 61 70 70 2f 73 65 72 76 69 63 65 73 2f 43 61 6c 6c 52 65 63 6f 72 64 65 72 53 65 72 76 69 63 65 } //00 00  com/android/system/app/services/CallRecorderService
	condition:
		any of ($a_*)
 
}