
rule MonitoringTool_AndroidOS_Nidb_D_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Nidb.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 65 6e 64 41 6c 6c 4e 65 77 4d 65 73 73 61 67 65 73 44 61 74 61 54 6f 53 65 72 76 65 72 } //01 00  sendAllNewMessagesDataToServer
		$a_00_1 = {73 65 6e 64 41 6c 6c 41 70 70 4c 6f 67 73 44 61 74 61 54 6f 53 65 72 76 65 72 } //01 00  sendAllAppLogsDataToServer
		$a_00_2 = {69 73 52 65 63 6f 72 64 69 6e 67 43 61 6c 6c } //01 00  isRecordingCall
		$a_00_3 = {63 68 65 63 6b 41 70 70 43 68 61 74 49 6e 73 74 61 6c 6c 65 64 } //01 00  checkAppChatInstalled
		$a_00_4 = {69 73 43 6f 72 65 53 70 79 53 65 72 76 69 63 65 52 75 6e 6e 69 6e 67 } //00 00  isCoreSpyServiceRunning
	condition:
		any of ($a_*)
 
}