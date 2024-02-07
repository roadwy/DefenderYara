
rule MonitoringTool_AndroidOS_GmSpy_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/GmSpy.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 70 79 43 61 6d 65 72 61 53 65 72 76 69 63 65 } //01 00  SpyCameraService
		$a_00_1 = {64 6f 77 6e 6c 6f 61 64 4d 6f 6e 69 74 6f 72 53 65 72 76 69 63 65 } //01 00  downloadMonitorService
		$a_00_2 = {73 74 6f 70 57 61 74 63 68 69 6e 67 } //01 00  stopWatching
		$a_00_3 = {61 70 70 70 69 63 6b 65 72 } //01 00  apppicker
		$a_00_4 = {53 63 72 65 65 6e 52 65 63 6f 72 64 65 72 53 65 72 76 69 63 65 } //01 00  ScreenRecorderService
		$a_00_5 = {44 61 74 61 55 70 6c 6f 61 64 52 65 63 65 69 76 65 72 } //01 00  DataUploadReceiver
		$a_00_6 = {76 69 64 65 6f 43 61 70 74 75 72 65 72 } //00 00  videoCapturer
	condition:
		any of ($a_*)
 
}