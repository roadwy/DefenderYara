
rule Backdoor_AndroidOS_Sniffer_A_MTB{
	meta:
		description = "Backdoor:AndroidOS/Sniffer.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 6d 73 43 61 6c 6c 52 65 63 65 69 76 65 72 } //1 SmsCallReceiver
		$a_01_1 = {55 72 6c 53 6e 69 66 66 65 72 } //1 UrlSniffer
		$a_01_2 = {53 4d 53 4f 62 73 65 72 76 65 72 } //1 SMSObserver
		$a_01_3 = {4e 6f 74 69 66 69 63 61 74 69 6f 6e 4c 69 73 74 65 6e 65 72 } //1 NotificationListener
		$a_01_4 = {2f 55 70 6c 6f 61 64 43 61 70 74 75 72 65 49 6d 61 67 65 } //1 /UploadCaptureImage
		$a_01_5 = {2f 53 61 76 65 43 61 6c 6c 52 65 63 6f 72 64 65 72 } //1 /SaveCallRecorder
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}