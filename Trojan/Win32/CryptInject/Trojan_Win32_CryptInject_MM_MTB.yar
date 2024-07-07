
rule Trojan_Win32_CryptInject_MM_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 95 fa fb ff ff 83 c3 04 88 54 3e 02 83 c6 03 8b 0d 90 01 04 3b d9 90 00 } //1
		$a_02_1 = {69 c9 fd 43 03 00 81 c1 c3 9e 26 00 8b c1 89 0d 90 01 04 c1 e8 10 30 04 13 43 3b df 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}