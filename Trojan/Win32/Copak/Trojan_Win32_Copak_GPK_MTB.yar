
rule Trojan_Win32_Copak_GPK_MTB{
	meta:
		description = "Trojan:Win32/Copak.GPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {68 d8 85 40 00 59 90 02 50 81 e1 ff 00 00 00 90 00 } //4
		$a_03_1 = {68 d8 85 40 00 58 90 02 50 81 e2 ff 00 00 00 90 00 } //4
		$a_03_2 = {68 d8 85 40 00 5a 90 02 50 81 e2 ff 00 00 00 90 00 } //4
		$a_03_3 = {ba d8 85 40 00 b8 90 02 50 81 e2 ff 00 00 00 90 00 } //4
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*4+(#a_03_2  & 1)*4+(#a_03_3  & 1)*4) >=4
 
}