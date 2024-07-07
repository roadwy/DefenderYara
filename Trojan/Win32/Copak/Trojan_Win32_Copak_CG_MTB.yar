
rule Trojan_Win32_Copak_CG_MTB{
	meta:
		description = "Trojan:Win32/Copak.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {4b 29 df e8 90 02 04 31 02 81 c2 01 00 00 00 39 ca 75 e7 90 00 } //2
		$a_01_1 = {01 f6 31 17 81 c7 01 00 00 00 39 c7 75 e0 } //2
		$a_01_2 = {21 c8 31 3e 81 c6 01 00 00 00 01 c9 39 d6 75 de } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=2
 
}