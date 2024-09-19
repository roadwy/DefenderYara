
rule TrojanSpy_AndroidOS_Banker_AQ_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.AQ!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 53 6d 73 74 6f 65 72 76 65 72 } //1 sendSmstoerver
		$a_01_1 = {63 6f 6d 2f 6d 79 63 61 72 64 2f 69 63 76 } //1 com/mycard/icv
		$a_01_2 = {53 6d 73 52 65 70 6f 73 69 74 6f 72 79 } //1 SmsRepository
		$a_01_3 = {72 72 64 64 2e 63 6f 2e 69 6e 2f 61 64 6d 69 6e 5f 70 61 6e 65 6c 2f } //1 rrdd.co.in/admin_panel/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}