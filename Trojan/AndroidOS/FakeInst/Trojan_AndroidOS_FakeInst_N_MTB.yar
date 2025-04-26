
rule Trojan_AndroidOS_FakeInst_N_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeInst.N!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6f 35 73 6d 73 2e 63 6f 6d 2f 61 70 69 2f 74 72 61 63 65 2f } //1 o5sms.com/api/trace/
		$a_01_1 = {61 67 72 65 65 2e 74 78 74 } //1 agree.txt
		$a_01_2 = {72 61 74 65 73 2e 70 68 70 } //1 rates.php
		$a_01_3 = {64 61 74 61 2e 72 65 73 } //1 data.res
		$a_01_4 = {73 65 6e 64 54 65 78 74 4d 65 73 73 61 67 65 } //1 sendTextMessage
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}