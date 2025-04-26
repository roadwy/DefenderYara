
rule Trojan_Win32_Tapaoux_L{
	meta:
		description = "Trojan:Win32/Tapaoux.L,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {6a 0a 99 59 f7 f9 69 d2 e8 03 00 00 52 ff d3 6a 02 58 39 45 88 75 0e 89 75 88 89 } //1
		$a_01_1 = {c6 45 ec 35 c6 45 ed 62 c6 45 ee 62 c6 45 ef 5f c6 45 f0 62 c6 45 f1 10 c6 45 f2 33 c6 45 f3 5f c6 45 f4 54 c6 45 f5 55 c6 45 f6 00 e8 } //1
		$a_01_2 = {76 0b 80 44 05 ec 10 40 3b 45 e8 72 f5 39 75 7c 76 31 57 } //1
		$a_01_3 = {53 53 ff d7 89 44 24 24 39 5c 24 1c 74 20 39 5c 24 20 74 1a 3b c3 74 16 8b } //1
		$a_03_4 = {c6 45 fc 51 c6 45 fd 52 c6 45 fe 00 e8 ?? ?? ?? ?? 89 45 f0 83 c4 14 33 c0 39 75 f0 7e 0b 80 44 05 f4 13 40 3b 45 f0 7c f5 39 75 e8 7e 29 89 5d ec } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}