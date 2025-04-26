
rule TrojanSpy_AndroidOS_SmsThief_E_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 74 65 73 74 2f 73 6d 73 2f 48 65 61 64 6c 65 73 73 53 6d 73 53 65 6e 64 53 65 72 76 69 63 65 3b } //1 Lcom/test/sms/HeadlessSmsSendService;
		$a_00_1 = {2f 73 6d 73 2f 53 6d 73 4c 69 73 74 65 6e 65 72 3b } //1 /sms/SmsListener;
		$a_00_2 = {2f 73 6d 73 2e 70 68 70 } //1 /sms.php
		$a_00_3 = {69 6e 63 6f 6d 69 6e 67 20 6d 65 73 73 61 67 65 } //1 incoming message
		$a_00_4 = {67 65 74 4f 72 69 67 69 6e 61 74 69 6e 67 41 64 64 72 65 73 73 } //1 getOriginatingAddress
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}