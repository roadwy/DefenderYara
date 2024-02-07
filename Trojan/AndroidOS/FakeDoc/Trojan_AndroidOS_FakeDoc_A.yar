
rule Trojan_AndroidOS_FakeDoc_A{
	meta:
		description = "Trojan:AndroidOS/FakeDoc.A,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 7a 61 6e 61 6c 79 74 69 63 73 2f 73 6d 73 2f 53 6d 73 52 65 63 65 69 76 65 72 53 65 72 76 69 63 65 3b } //02 00  Lcom/zanalytics/sms/SmsReceiverService;
		$a_00_1 = {53 6d 73 5f 52 65 63 65 69 76 65 5f 54 72 61 63 6b 69 6e 67 } //02 00  Sms_Receive_Tracking
		$a_00_2 = {68 61 6e 64 6c 65 53 65 6e 64 53 6d 73 20 2d 20 } //01 00  handleSendSms - 
		$a_00_3 = {6d 79 6b 69 6c 6c 73 2e 64 74 6b 65 } //01 00  mykills.dtke
		$a_00_4 = {4c 63 6f 6d 2f 65 78 74 65 6e 64 2f 62 61 74 74 65 72 79 2f 53 70 6c 61 73 68 3b } //00 00  Lcom/extend/battery/Splash;
	condition:
		any of ($a_*)
 
}