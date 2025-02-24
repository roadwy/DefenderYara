
rule Trojan_Win32_Casbaneiro_GTN_MTB{
	meta:
		description = "Trojan:Win32/Casbaneiro.GTN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {20 20 20 20 20 20 20 20 00 42 b3 04 00 40 a9 00 00 a6 52 } //5
		$a_01_1 = {40 2e 69 64 61 74 61 00 00 00 10 00 00 00 80 89 06 00 06 00 00 00 } //5
		$a_01_2 = {40 00 00 40 2e 69 64 61 74 61 00 00 00 10 00 00 00 50 89 06 00 06 00 00 00 22 de } //10
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*10) >=10
 
}