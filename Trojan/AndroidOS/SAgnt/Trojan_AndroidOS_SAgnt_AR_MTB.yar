
rule Trojan_AndroidOS_SAgnt_AR_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.AR!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 0a 00 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 73 6d 73 6c 69 73 74 65 6e 65 72 61 70 70 } //5 Lcom/example/smslistenerapp
		$a_01_1 = {4c 63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 6d 79 61 70 70 6c 69 63 61 74 69 6f 6e 2f 53 6d 73 53 75 63 63 65 73 73 41 63 74 69 76 69 74 79 } //5 Lcom/example/myapplication/SmsSuccessActivity
		$a_01_2 = {4c 63 6f 6d 2f 62 72 6f 77 73 65 72 2f 77 65 62 32 33 2f 53 6d 73 52 65 63 65 69 76 65 72 41 63 74 69 76 69 74 79 } //5 Lcom/browser/web23/SmsReceiverActivity
		$a_01_3 = {4c 63 6f 6d 2f 67 6f 6f 67 6c 65 2f 67 6f 2f 53 6d 73 52 65 63 65 69 76 65 72 } //5 Lcom/google/go/SmsReceiver
		$a_01_4 = {74 74 70 73 3a 2f 2f 77 77 77 2e 73 6e 65 74 61 70 69 73 2e 63 6f 6d 2f 61 70 69 2f } //1 ttps://www.snetapis.com/api/
		$a_01_5 = {73 6d 73 2d 74 65 73 74 2f 69 6e 64 65 78 2e 70 68 70 } //1 sms-test/index.php
		$a_01_6 = {74 68 69 73 5f 73 6d 73 5f 72 65 63 65 69 76 65 72 5f 61 70 70 } //1 this_sms_receiver_app
		$a_01_7 = {53 6d 73 52 65 63 65 69 76 65 72 41 63 74 69 76 69 74 79 } //1 SmsReceiverActivity
		$a_01_8 = {2f 69 6e 73 74 61 6c 6c 2e 70 68 70 } //1 /install.php
		$a_01_9 = {74 74 70 73 3a 2f 2f 77 77 77 2e 63 6f 6d 6e 65 74 6f 72 67 69 6e 66 6f 2e 63 6f 6d 2f 64 61 74 61 } //1 ttps://www.comnetorginfo.com/data
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=8
 
}