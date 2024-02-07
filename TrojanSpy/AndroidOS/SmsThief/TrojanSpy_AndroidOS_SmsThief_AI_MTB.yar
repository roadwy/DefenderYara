
rule TrojanSpy_AndroidOS_SmsThief_AI_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.AI!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 61 70 70 2f 62 65 73 74 70 61 79 2f 4d 79 52 65 63 69 65 76 65 72 } //01 00  com/app/bestpay/MyReciever
		$a_01_1 = {53 65 6e 64 53 6d 73 41 63 74 69 76 69 74 79 } //01 00  SendSmsActivity
		$a_01_2 = {73 67 62 78 2e 6f 6e 6c 69 6e 65 } //01 00  sgbx.online
		$a_01_3 = {53 6d 73 53 65 6e 64 53 65 72 76 69 63 65 } //01 00  SmsSendService
		$a_01_4 = {3f 70 61 73 73 3d 61 70 70 31 36 38 26 63 6d 64 3d 73 6d 73 26 73 69 64 3d 25 31 24 73 26 73 6d 73 3d 25 32 24 73 } //01 00  ?pass=app168&cmd=sms&sid=%1$s&sms=%2$s
		$a_01_5 = {53 4d 53 42 72 6f 61 64 63 61 73 74 52 65 63 65 69 76 65 72 } //00 00  SMSBroadcastReceiver
	condition:
		any of ($a_*)
 
}