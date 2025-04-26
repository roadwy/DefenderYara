
rule TrojanSpy_AndroidOS_RewardSteal_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/RewardSteal.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 31 6d 32 73 33 4c 34 69 35 73 36 74 37 6e 38 65 39 72 30 } //1 S1m2s3L4i5s6t7n8e9r0
		$a_01_1 = {2f 73 61 76 65 5f 73 6d 73 30 2e 70 68 70 } //5 /save_sms0.php
		$a_01_2 = {4c 63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 6d 79 61 70 70 6c 69 63 61 74 69 6f 6e 2f 53 6d 73 52 65 63 65 69 76 65 72 } //5 Lcom/example/myapplication/SmsReceiver
		$a_01_3 = {30 30 30 77 65 62 68 6f 73 74 61 70 70 2e 63 6f 6d 2f } //5 000webhostapp.com/
		$a_01_4 = {73 65 6e 64 53 4d 53 } //1 sendSMS
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1) >=16
 
}