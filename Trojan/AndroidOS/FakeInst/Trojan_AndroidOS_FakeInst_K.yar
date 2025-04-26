
rule Trojan_AndroidOS_FakeInst_K{
	meta:
		description = "Trojan:AndroidOS/FakeInst.K,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {46 4c 41 47 5f 43 4f 4e 46 49 52 4d 5f 4b 57 31 } //2 FLAG_CONFIRM_KW1
		$a_01_1 = {73 75 62 2f 43 6f 6e 66 69 72 6d 53 6d 73 52 65 63 65 69 76 65 72 } //2 sub/ConfirmSmsReceiver
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}