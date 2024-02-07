
rule Trojan_AndroidOS_SpyBanker_K{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.K,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 08 00 00 04 00 "
		
	strings :
		$a_01_0 = {73 61 76 65 5f 73 6d 73 30 2e 70 68 70 } //02 00  save_sms0.php
		$a_01_1 = {4c 63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 75 70 69 2f 53 6d 73 52 65 63 65 69 76 65 72 } //02 00  Lcom/example/upi/SmsReceiver
		$a_01_2 = {4c 63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 6d 79 61 70 70 6c 69 63 61 74 69 6f 6e 2f 53 6d 73 4c 69 73 74 6e 65 72 } //02 00  Lcom/example/myapplication/SmsListner
		$a_01_3 = {4c 63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 75 70 69 2f 53 6d 73 4c 69 73 74 6e 65 72 } //02 00  Lcom/example/upi/SmsListner
		$a_01_4 = {63 6f 6d 2e 73 74 75 64 79 37 36 35 34 37 73 74 75 64 79 2e 61 70 70 6c 69 63 61 74 69 6f 6e 2e 76 69 64 68 69 79 61 2e 6d 79 61 70 70 6c 69 63 61 74 69 6f 6e } //02 00  com.study76547study.application.vidhiya.myapplication
		$a_01_5 = {2f 76 69 64 68 69 79 61 2f 6d 79 61 70 70 6c 69 63 61 74 69 6f 6e 2f 53 6d 73 52 65 63 69 76 65 72 } //02 00  /vidhiya/myapplication/SmsReciver
		$a_01_6 = {4c 6e 65 74 2f 74 72 69 63 65 73 2f 73 6d 73 2f } //02 00  Lnet/trices/sms/
		$a_01_7 = {4c 63 6f 6d 2f 61 62 63 38 39 38 64 2f 77 65 62 6d 61 73 74 65 72 2f 53 6d 73 52 65 63 65 69 76 65 72 } //00 00  Lcom/abc898d/webmaster/SmsReceiver
	condition:
		any of ($a_*)
 
}