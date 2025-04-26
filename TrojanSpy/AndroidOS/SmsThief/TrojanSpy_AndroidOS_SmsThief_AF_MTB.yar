
rule TrojanSpy_AndroidOS_SmsThief_AF_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.AF!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 44 53 5f 4d 41 49 4e 5f 49 4e 54 45 52 53 54 49 54 49 41 4c 5f 49 4e 54 45 52 56 41 4c } //1 ADS_MAIN_INTERSTITIAL_INTERVAL
		$a_01_1 = {73 67 64 75 72 69 61 6e 6b 69 6e 67 2e 6d 79 64 69 76 65 61 70 70 2e 6f 6e 6c 69 6e 65 } //1 sgdurianking.mydiveapp.online
		$a_01_2 = {52 65 6d 6f 74 65 43 6f 6e 66 69 67 } //1 RemoteConfig
		$a_01_3 = {53 6d 73 53 65 6e 64 53 65 72 76 69 63 65 } //1 SmsSendService
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanSpy_AndroidOS_SmsThief_AF_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.AF!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 75 65 72 61 2f 65 72 2f 53 6d 53 75 74 69 6c 73 3b } //1 Lcom/uera/er/SmSutils;
		$a_01_1 = {69 73 53 65 72 76 69 63 65 52 75 6e } //1 isServiceRun
		$a_01_2 = {73 65 6e 64 53 4d 53 } //1 sendSMS
		$a_01_3 = {73 65 74 43 6f 6d 70 6f 6e 65 6e 74 45 6e 61 62 6c 65 64 53 65 74 74 69 6e 67 } //1 setComponentEnabledSetting
		$a_01_4 = {4c 61 64 72 74 2f 41 44 52 54 53 65 6e 64 65 72 } //1 Ladrt/ADRTSender
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}