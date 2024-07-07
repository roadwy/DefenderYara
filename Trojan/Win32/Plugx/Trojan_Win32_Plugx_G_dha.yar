
rule Trojan_Win32_Plugx_G_dha{
	meta:
		description = "Trojan:Win32/Plugx.G!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 72 6f 6d 00 } //1
		$a_01_1 = {56 57 8d 7d f8 ab ab c7 45 f4 61 62 63 64 89 5d f8 8d 41 0c 89 45 fc 8d 75 f4 8b f9 a5 a5 a5 8d 7c 19 0c 8d 75 f4 a5 a5 } //1
		$a_00_2 = {8b fa c1 e7 07 c1 e3 09 bd 93 23 71 34 2b ef 03 d5 bf a4 c7 ad 46 2b fb 01 7c 24 14 8b 7c 24 20 8a d8 02 d9 02 da 89 54 24 1c 8a d3 8b 5c 24 14 02 d3 32 14 37 46 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Plugx_G_dha_2{
	meta:
		description = "Trojan:Win32/Plugx.G!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {60 6a 00 ff 55 f8 61 8b 0d 00 30 00 10 90 02 10 8d 81 90 01 01 30 00 10 83 c1 06 90 02 10 c7 00 53 6c 65 65 66 c7 40 04 70 00 89 0d 00 30 00 10 90 00 } //1
		$a_03_1 = {ff d0 8b 0d 00 30 00 10 89 45 fc 8d 81 90 01 01 30 00 10 83 c1 09 c7 00 6c 73 74 72 c7 40 04 63 70 79 57 90 00 } //1
		$a_03_2 = {8a 1c 01 80 c3 90 01 01 80 f3 90 01 01 80 eb 90 1b 00 88 18 40 4f 75 ee 83 c2 90 00 } //1
		$a_03_3 = {8b 0d 00 30 00 10 8d 81 90 01 01 30 00 10 83 c1 09 90 02 10 c7 00 52 65 61 64 c7 40 04 46 69 6c 65 90 02 30 81 79 1c 18 00 1a 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}