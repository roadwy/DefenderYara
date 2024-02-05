
rule Trojan_Win32_Tibs_JN{
	meta:
		description = "Trojan:Win32/Tibs.JN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 02 56 69 72 74 } //01 00 
		$a_01_1 = {8d 90 a0 00 00 00 8b 02 8b 00 8d 50 08 } //01 00 
		$a_01_2 = {8b 10 81 c2 45 23 01 00 } //01 00 
		$a_01_3 = {8b 43 04 8b 44 04 11 39 d8 74 03 8b 45 fc } //01 00 
		$a_03_4 = {87 ca 31 d2 41 42 81 fa 90 01 04 75 f6 c3 90 00 } //01 00 
		$a_03_5 = {89 d1 01 c1 31 d2 83 c1 01 83 c2 01 81 fa 90 01 04 75 f2 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}