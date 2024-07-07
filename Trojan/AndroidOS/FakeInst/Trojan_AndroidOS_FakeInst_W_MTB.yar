
rule Trojan_AndroidOS_FakeInst_W_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeInst.W!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 45 4e 54 5f 53 4d 53 5f 4e 55 4d 42 45 52 5f 4b 45 59 } //1 SENT_SMS_NUMBER_KEY
		$a_01_1 = {46 49 52 53 54 5f 53 45 4e 44 5f 31 30 } //1 FIRST_SEND_10
		$a_01_2 = {42 45 4c 4c 4f 52 55 53 53 5f 49 44 } //1 BELLORUSS_ID
		$a_01_3 = {63 6f 6d 2e 67 6f 6f 67 6c 65 61 70 69 2e 63 6f 76 65 72 } //1 com.googleapi.cover
		$a_01_4 = {69 73 4d 54 53 52 46 } //1 isMTSRF
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}