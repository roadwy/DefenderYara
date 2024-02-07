
rule Trojan_Win32_Doina_DW_MTB{
	meta:
		description = "Trojan:Win32/Doina.DW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 81 f6 5d 52 81 c9 6e 00 46 f7 89 f9 38 de 66 d3 ee 29 d9 66 0f be f2 f9 89 e6 f9 83 ef 04 66 0f a3 ce f9 f8 ff 37 e8 90 01 04 84 f1 f9 39 df e9 90 00 } //01 00 
		$a_01_1 = {bd f2 55 b7 f2 10 16 5f ed 33 19 bb 19 34 32 7f } //01 00 
		$a_01_2 = {91 1b 0a 88 d2 19 e2 b4 9d fa fc d7 2e f8 30 66 2e b2 19 14 2e f8 30 76 95 7e } //01 00 
		$a_01_3 = {bf d3 ec 94 1e e6 aa 34 75 f5 01 e7 5a 8b cc 28 7a 72 c3 e0 } //01 00 
		$a_01_4 = {50 2e 76 6d 70 30 } //01 00  P.vmp0
		$a_01_5 = {63 6b 6d 53 5b 71 26 77 4c } //01 00  ckmS[q&wL
		$a_01_6 = {57 56 4b 4f 48 21 6e } //00 00  WVKOH!n
	condition:
		any of ($a_*)
 
}