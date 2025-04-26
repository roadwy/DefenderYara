
rule MonitoringTool_MacOS_Spyrix_B_MTB{
	meta:
		description = "MonitoringTool:MacOS/Spyrix.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {64 61 73 68 62 6f 61 72 64 2e 73 70 79 72 69 78 2e 63 6f 6d 2f 63 6c 69 65 6e 74 2d 74 65 63 68 2d 6c 6f 67 73 2f 67 65 74 2d 6c 61 73 74 2d 74 69 6d 65 3f 63 6f 6d 70 5f 69 64 3d } //1 dashboard.spyrix.com/client-tech-logs/get-last-time?comp_id=
		$a_01_1 = {73 70 79 72 69 78 2e 6e 65 74 2f 75 73 72 2f 6d 6f 6e 69 74 6f 72 2f 75 70 6c 6f 61 64 5f 70 72 67 2e 70 68 70 } //1 spyrix.net/usr/monitor/upload_prg.php
		$a_01_2 = {69 73 4d 6f 6e 69 74 6f 72 69 6e 67 4b 65 79 6c 6f 67 67 65 72 } //1 isMonitoringKeylogger
		$a_01_3 = {6d 6f 6e 69 74 6f 72 69 6e 67 41 75 64 69 6f 44 65 76 69 63 65 73 } //1 monitoringAudioDevices
		$a_01_4 = {76 69 64 65 6f 57 65 62 43 61 6d 52 65 63 6f 72 64 65 72 4d 61 6e 61 67 65 72 } //1 videoWebCamRecorderManager
		$a_01_5 = {73 65 74 74 69 6e 67 73 3a 65 6e 61 62 6c 65 43 61 6c 6c 52 65 63 6f 72 64 69 6e 67 } //1 settings:enableCallRecording
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}