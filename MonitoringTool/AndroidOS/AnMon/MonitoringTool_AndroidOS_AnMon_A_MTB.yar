
rule MonitoringTool_AndroidOS_AnMon_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/AnMon.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 4e 44 52 4f 49 44 5f 4d 4f 4e 49 54 4f 52 5f 43 48 45 43 4b 45 52 } //1 ANDROID_MONITOR_CHECKER
		$a_01_1 = {73 63 72 65 65 6e 5f 63 61 70 74 75 72 65 5f 72 65 71 75 65 73 74 } //1 screen_capture_request
		$a_01_2 = {64 6f 77 6c 6f 61 64 5f 6d 6f 6e 69 74 6f 72 63 68 65 63 6b 65 72 } //1 dowload_monitorchecker
		$a_01_3 = {4b 65 79 4c 6f 67 67 65 72 41 70 70 73 } //1 KeyLoggerApps
		$a_01_4 = {72 65 63 5f 73 63 72 65 65 6e 5f 63 61 6d 5f 77 68 61 74 63 68 } //1 rec_screen_cam_whatch
		$a_01_5 = {73 65 6e 64 5f 64 61 74 61 5f 74 6f 5f 73 65 72 76 65 72 } //1 send_data_to_server
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}