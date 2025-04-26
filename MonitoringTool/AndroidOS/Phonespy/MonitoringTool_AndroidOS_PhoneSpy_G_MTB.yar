
rule MonitoringTool_AndroidOS_PhoneSpy_G_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/PhoneSpy.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 73 70 61 5f 6d 6f 74 5f 61 70 70 2f 61 6c 61 72 6d } //1 com/spa_mot_app/alarm
		$a_01_1 = {43 6c 6f 73 65 49 6e 74 65 72 6e 65 74 41 6e 64 47 70 73 } //1 CloseInternetAndGps
		$a_01_2 = {43 61 6c 6c 52 65 63 6f 72 64 69 6e 67 53 65 72 76 69 63 65 } //1 CallRecordingService
		$a_01_3 = {73 6d 73 5f 70 68 6f 6e 65 5f 6c 69 73 74 } //1 sms_phone_list
		$a_01_4 = {53 65 72 76 65 72 43 6f 6d 6d 75 6e 69 63 61 74 65 } //1 ServerCommunicate
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}