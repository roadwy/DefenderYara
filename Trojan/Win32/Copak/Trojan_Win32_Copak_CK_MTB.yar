
rule Trojan_Win32_Copak_CK_MTB{
	meta:
		description = "Trojan:Win32/Copak.CK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {4b 09 db e8 [0-04] 31 07 81 c7 01 00 00 00 39 f7 75 e6 } //2
		$a_03_1 = {31 06 81 c1 [0-04] 29 cf 46 81 e9 [0-04] 81 e9 [0-04] 39 de 75 d8 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=2
 
}