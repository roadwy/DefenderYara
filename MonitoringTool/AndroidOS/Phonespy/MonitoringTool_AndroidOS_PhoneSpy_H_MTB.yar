
rule MonitoringTool_AndroidOS_PhoneSpy_H_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/PhoneSpy.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 73 70 74 72 61 6b 61 70 70 70 2f 61 6c 61 72 6d 2f 53 4d 53 52 65 63 65 69 76 65 72 } //1 com/sptrakappp/alarm/SMSReceiver
		$a_01_1 = {52 65 6d 6f 74 65 52 65 63 6f 72 64 69 6e 67 53 65 72 76 69 63 65 } //1 RemoteRecordingService
		$a_01_2 = {53 63 72 65 65 6e 43 68 61 6e 63 65 64 52 65 63 65 69 76 65 72 } //1 ScreenChancedReceiver
		$a_01_3 = {63 61 6c 6c 5f 70 68 6f 6e 65 5f 6c 69 73 74 } //1 call_phone_list
		$a_01_4 = {64 69 73 61 62 6c 65 5f 62 72 6f 77 73 65 72 } //1 disable_browser
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}