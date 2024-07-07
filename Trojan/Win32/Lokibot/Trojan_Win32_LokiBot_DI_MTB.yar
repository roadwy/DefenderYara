
rule Trojan_Win32_LokiBot_DI_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.DI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {57 6a 40 68 90 02 40 8b 07 8a 98 90 01 04 90 05 10 01 90 8a 15 90 01 04 8b c3 e8 90 01 04 a2 90 01 04 90 05 10 01 90 8a 1d 90 01 04 a1 90 01 04 89 07 90 05 10 01 90 8b c3 e8 90 01 04 90 05 10 01 90 a1 90 01 04 89 07 8b 07 83 c0 02 a3 90 01 04 90 05 10 01 90 46 81 fe 90 01 04 75 90 00 } //1
		$a_03_1 = {be e8 dd 11 0c 90 05 10 01 90 4e 75 f9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}