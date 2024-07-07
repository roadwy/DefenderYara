
rule Trojan_Win32_TitanStealer_PA_MTB{
	meta:
		description = "Trojan:Win32/TitanStealer.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //1 Go build ID:
		$a_03_1 = {5f 2f 43 5f 2f 55 73 65 72 73 2f 90 02 15 2f 44 65 73 6b 74 6f 70 2f 73 74 65 61 6c 65 72 5f 76 90 00 } //2
		$a_01_2 = {37 37 2e 37 33 2e 31 33 33 2e 38 38 } //2 77.73.133.88
		$a_03_3 = {01 d6 89 f0 c1 fe 1f c1 ee 17 01 c6 c1 fe 09 c1 e6 09 29 f0 89 05 90 01 04 01 d3 8b 44 24 90 01 01 89 ea 39 da 7e 90 00 } //3
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2+(#a_03_3  & 1)*3) >=8
 
}