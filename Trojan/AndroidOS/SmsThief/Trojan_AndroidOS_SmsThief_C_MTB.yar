
rule Trojan_AndroidOS_SmsThief_C_MTB{
	meta:
		description = "Trojan:AndroidOS/SmsThief.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 74 65 73 74 2f 73 6d 73 2f 43 61 6c 6c 41 70 69 53 65 72 76 69 63 65 3b } //1 Lcom/test/sms/CallApiService;
		$a_00_1 = {73 69 63 75 72 65 7a 7a 61 69 74 61 6c 69 61 2e 64 75 63 6b 64 6e 73 2e 6f 72 67 } //1 sicurezzaitalia.duckdns.org
		$a_00_2 = {2f 53 4d 53 2f 73 6d 73 2e 70 68 70 } //1 /SMS/sms.php
		$a_00_3 = {6d 73 67 42 6f 64 79 } //1 msgBody
		$a_00_4 = {2f 48 65 61 64 6c 65 73 73 53 6d 73 53 65 6e 64 53 65 72 76 69 63 65 3b } //1 /HeadlessSmsSendService;
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}