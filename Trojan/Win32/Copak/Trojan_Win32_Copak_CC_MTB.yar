
rule Trojan_Win32_Copak_CC_MTB{
	meta:
		description = "Trojan:Win32/Copak.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 08 29 fe 81 ee [0-04] 40 89 f7 89 f7 39 d8 75 d8 } //2
		$a_01_1 = {89 c8 31 16 46 39 de 75 e5 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}