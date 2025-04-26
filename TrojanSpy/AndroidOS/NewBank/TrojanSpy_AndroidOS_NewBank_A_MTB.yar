
rule TrojanSpy_AndroidOS_NewBank_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/NewBank.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 6e 65 77 62 61 6e 6b 2f 62 61 6e 6b 21 73 61 76 65 42 61 6e 6b 2e 64 6f } //1 /newbank/bank!saveBank.do
		$a_01_1 = {53 4d 53 53 65 72 76 69 63 65 4c 61 66 74 65 72 } //1 SMSServiceLafter
		$a_01_2 = {67 65 74 53 6d 73 41 6e 64 53 65 6e 64 42 61 63 6b } //1 getSmsAndSendBack
		$a_01_3 = {6e 65 77 62 61 6e 6b 2f 63 6f 6d 2e 61 6e 64 72 6f 69 64 2e 73 6d 73 2e 61 70 6b } //1 newbank/com.android.sms.apk
		$a_01_4 = {62 61 6e 6b 21 73 61 76 65 53 6d 73 2e 64 6f } //1 bank!saveSms.do
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}