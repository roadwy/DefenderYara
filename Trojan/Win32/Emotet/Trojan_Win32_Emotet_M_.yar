
rule Trojan_Win32_Emotet_M_{
	meta:
		description = "Trojan:Win32/Emotet.M!!Emotet.gen!B,SIGNATURE_TYPE_ARHSTR_EXT,28 00 28 00 04 00 00 "
		
	strings :
		$a_00_0 = {c1 e7 03 83 e7 18 89 4d d4 89 f9 d3 e6 31 c6 8b 45 ec 8a 0c 02 8b 55 f0 88 0a 8b 7d d4 83 c7 01 } //10
		$a_03_1 = {15 18 00 00 00 31 ?? 8b ?? 30 8b ?? 0c } //10
		$a_03_2 = {74 0a a1 18 30 ?? 00 ff d0 } //10
		$a_01_3 = {8b 30 8b 78 04 8b 58 08 8b 68 0c 8b 60 10 8b 40 14 ff e0 } //10
	condition:
		((#a_00_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10+(#a_01_3  & 1)*10) >=40
 
}