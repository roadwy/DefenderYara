
rule MonitoringTool_AndroidOS_Dromon_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Dromon.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {69 6e 66 6f 5f 70 72 6f 67 5f 73 6d 73 5f 63 6f 6d 61 6e 64 } //1 info_prog_sms_comand
		$a_01_1 = {53 63 72 65 65 6e 43 61 70 74 75 72 65 50 65 72 6d 69 73 73 69 6f 6e 41 63 74 69 76 69 74 79 } //1 ScreenCapturePermissionActivity
		$a_01_2 = {69 6e 66 6f 5f 70 72 6f 67 5f 63 61 6c 6c 5f 72 65 63 6f 72 64 5f 73 75 63 63 65 73 73 } //1 info_prog_call_record_success
		$a_01_3 = {69 6e 66 6f 5f 73 65 74 69 6e 67 73 5f 4b 65 79 4c 6f 67 67 65 72 41 70 70 73 } //1 info_setings_KeyLoggerApps
		$a_01_4 = {69 6e 66 6f 5f 73 65 74 69 6e 67 73 5f 65 6e 61 62 6c 65 43 61 6c 6c 73 } //1 info_setings_enableCalls
		$a_01_5 = {69 6e 66 6f 5f 71 75 65 75 65 5f 73 65 6e 64 5f 64 61 74 61 5f 74 6f 5f 73 65 72 76 65 72 } //1 info_queue_send_data_to_server
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}