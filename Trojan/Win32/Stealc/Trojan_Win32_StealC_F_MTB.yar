
rule Trojan_Win32_StealC_F_MTB{
	meta:
		description = "Trojan:Win32/StealC.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 d1 5a 01 f1 31 01 8b } //2
		$a_01_1 = {01 f0 01 18 58 81 } //2
		$a_03_2 = {01 de 5b 57 56 be ?? ?? ?? ?? bf ?? ?? ?? ?? 29 f7 5e 29 f9 5f } //4
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*4) >=8
 
}