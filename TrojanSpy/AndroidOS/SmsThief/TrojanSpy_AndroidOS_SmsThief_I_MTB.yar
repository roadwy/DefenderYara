
rule TrojanSpy_AndroidOS_SmsThief_I_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 73 79 73 74 65 6d 2f 53 4d 53 52 65 63 65 69 76 65 72 24 48 54 54 50 54 61 73 6b 3b } //01 00  /system/SMSReceiver$HTTPTask;
		$a_01_1 = {73 65 6e 64 56 69 61 53 4d 53 } //01 00  sendViaSMS
		$a_01_2 = {53 45 4e 44 5f 54 59 50 45 5f 48 54 54 50 5f 54 48 45 4e 5f 53 4d 53 } //01 00  SEND_TYPE_HTTP_THEN_SMS
		$a_01_3 = {61 62 6f 72 74 42 72 6f 61 64 63 61 73 74 } //01 00  abortBroadcast
		$a_01_4 = {70 65 72 66 6f 72 6d 41 63 74 69 6f 6e } //00 00  performAction
	condition:
		any of ($a_*)
 
}