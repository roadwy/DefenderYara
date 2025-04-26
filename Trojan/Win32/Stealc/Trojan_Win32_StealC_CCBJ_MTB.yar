
rule Trojan_Win32_StealC_CCBJ_MTB{
	meta:
		description = "Trojan:Win32/StealC.CCBJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 dd 33 de 33 d8 2b fb 8b c7 c1 e0 } //1
		$a_03_1 = {33 f3 31 74 24 ?? 8b 44 24 ?? 29 44 24 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}