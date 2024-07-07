
rule MonitoringTool_AndroidOS_FinSpy_A_xp{
	meta:
		description = "MonitoringTool:AndroidOS/FinSpy.A!xp,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {49 6e 73 74 61 6c 6c 65 64 20 4d 6f 64 75 6c 65 73 20 53 79 70 43 61 6c 6c } //1 Installed Modules SypCall
		$a_00_1 = {54 6c 76 54 79 70 65 43 6f 6e 66 69 67 56 6f 49 50 53 63 72 65 65 6e 73 68 6f 74 45 6e 61 62 6c 65 64 } //1 TlvTypeConfigVoIPScreenshotEnabled
		$a_00_2 = {53 74 61 72 74 53 63 72 65 65 6e 52 65 63 6f 72 64 69 6e 67 } //1 StartScreenRecording
		$a_00_3 = {53 65 6e 74 3a 20 47 65 74 52 65 63 6f 72 64 65 64 46 69 6c 65 73 52 65 70 6c 79 } //1 Sent: GetRecordedFilesReply
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}