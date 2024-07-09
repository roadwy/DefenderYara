
rule Trojan_Win32_Copak_GPL_MTB{
	meta:
		description = "Trojan:Win32/Copak.GPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {b8 d8 85 40 00 81 [0-50] 81 e0 ff 00 00 00 } //4
		$a_03_1 = {b8 d8 85 40 00 57 [0-50] 81 e0 ff 00 00 00 } //4
		$a_03_2 = {ba d8 85 40 00 83 [0-50] 81 e2 ff 00 00 00 } //4
		$a_03_3 = {68 d8 85 40 00 5f [0-50] 81 e7 ff 00 00 00 } //4
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*4+(#a_03_2  & 1)*4+(#a_03_3  & 1)*4) >=4
 
}