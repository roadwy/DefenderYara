
rule MonitoringTool_AndroidOS_PhoneSpy_C_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/PhoneSpy.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 6d 6f 6e 73 70 61 70 2f 61 6c 61 72 6d 2f 53 4d 53 52 65 63 65 69 76 65 72 } //01 00  Lcom/monspap/alarm/SMSReceiver
		$a_00_1 = {43 61 6c 6c 52 65 63 6f 72 64 69 6e 67 53 65 72 76 69 63 65 } //01 00  CallRecordingService
		$a_00_2 = {54 72 61 63 6b 4c 6f 63 61 74 69 6f 6e } //01 00  TrackLocation
		$a_00_3 = {4c 6f 63 61 74 69 6f 6e 53 61 76 65 } //01 00  LocationSave
		$a_00_4 = {50 68 6f 6e 65 43 61 6c 6c 52 65 63 65 69 76 65 72 } //01 00  PhoneCallReceiver
		$a_00_5 = {4e 45 57 5f 4f 55 54 47 4f 49 4e 47 5f 43 41 4c 4c } //00 00  NEW_OUTGOING_CALL
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_AndroidOS_PhoneSpy_C_MTB_2{
	meta:
		description = "MonitoringTool:AndroidOS/PhoneSpy.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 52 65 63 6f 72 64 69 6e 67 53 65 72 76 69 63 65 } //01 00  CallRecordingService
		$a_01_1 = {43 6f 6d 6d 75 6e 69 63 61 74 69 6f 6e 57 61 6b 65 66 75 6c 53 65 72 76 69 63 65 } //01 00  CommunicationWakefulService
		$a_01_2 = {53 63 72 65 65 6e 43 68 61 6e 63 65 64 52 65 63 65 69 76 65 72 } //01 00  ScreenChancedReceiver
		$a_01_3 = {46 69 6c 65 4d 61 6e 61 67 65 72 55 70 6c 6f 61 64 46 69 6c 65 } //01 00  FileManagerUploadFile
		$a_01_4 = {63 6f 6d 2f 73 70 61 5f 61 70 70 2f 61 6c 61 72 6d } //01 00  com/spa_app/alarm
		$a_01_5 = {54 72 61 63 6b 4c 6f 63 61 74 69 6f 6e } //00 00  TrackLocation
	condition:
		any of ($a_*)
 
}