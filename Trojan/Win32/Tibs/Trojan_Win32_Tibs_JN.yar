
rule Trojan_Win32_Tibs_JN{
	meta:
		description = "Trojan:Win32/Tibs.JN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 "
		
	strings :
		$a_01_0 = {c7 02 56 69 72 74 } //1
		$a_01_1 = {8d 90 a0 00 00 00 8b 02 8b 00 8d 50 08 } //1
		$a_01_2 = {8b 10 81 c2 45 23 01 00 } //1
		$a_01_3 = {8b 43 04 8b 44 04 11 39 d8 74 03 8b 45 fc } //1
		$a_03_4 = {87 ca 31 d2 41 42 81 fa ?? ?? ?? ?? 75 f6 c3 } //1
		$a_03_5 = {89 d1 01 c1 31 d2 83 c1 01 83 c2 01 81 fa ?? ?? ?? ?? 75 f2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=2
 
}