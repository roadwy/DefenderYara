
rule Trojan_Win32_VBInject_E_MTB{
	meta:
		description = "Trojan:Win32/VBInject.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_81_0 = {63 6c 69 65 6e 74 65 20 6e 75 65 76 6f 5c 73 74 75 62 5c 73 74 75 62 2e 76 62 70 } //3 cliente nuevo\stub\stub.vbp
		$a_81_1 = {76 61 71 75 69 74 61 6d 61 6c 61 } //3 vaquitamala
		$a_81_2 = {4a 50 45 47 73 6e 6f 6f 70 } //3 JPEGsnoop
		$a_81_3 = {44 65 63 72 79 70 74 42 79 74 65 } //3 DecryptByte
		$a_81_4 = {45 6e 63 72 79 70 74 53 74 72 69 6e 67 } //3 EncryptString
		$a_81_5 = {44 65 63 72 79 70 74 53 74 72 69 6e 67 } //3 DecryptString
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3) >=18
 
}