
rule MonitoringTool_AndroidOS_MyCellSpy_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/MyCellSpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 61 70 74 75 72 65 43 61 6c 6c } //01 00  captureCall
		$a_00_1 = {74 61 6b 65 50 68 6f 74 6f 53 63 72 65 65 6e 4c 6f 63 6b } //01 00  takePhotoScreenLock
		$a_00_2 = {43 68 61 74 55 70 6c 6f 61 64 } //01 00  ChatUpload
		$a_00_3 = {68 69 64 65 69 63 6f 6e } //01 00  hideicon
		$a_00_4 = {73 65 6e 64 5f 73 6d 73 } //01 00  send_sms
		$a_00_5 = {64 65 6c 65 74 65 5f 74 5f 63 68 61 74 5f 68 69 73 74 6f 72 79 } //01 00  delete_t_chat_history
		$a_00_6 = {63 72 65 61 74 65 73 63 72 65 65 6e 63 61 70 74 75 72 65 69 6e 74 65 6e 74 } //01 00  createscreencaptureintent
		$a_00_7 = {6d 79 2e 63 65 6c 6c 49 6e 66 6f 2e } //00 00  my.cellInfo.
	condition:
		any of ($a_*)
 
}