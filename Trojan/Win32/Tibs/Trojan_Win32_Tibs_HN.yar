
rule Trojan_Win32_Tibs_HN{
	meta:
		description = "Trojan:Win32/Tibs.HN,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 89 e5 8b 55 14 2b 55 10 42 4a 41 52 51 29 d2 52 52 ba 90 01 04 ff 12 59 5a 85 d2 75 eb 03 4d 0c 03 4d 08 81 e9 90 02 04 c9 c2 10 00 90 00 } //02 00 
		$a_03_1 = {66 ad c1 e0 04 c1 e0 0c 66 ad c1 c0 02 c1 c0 0b c1 c0 03 93 81 c3 90 01 04 89 d8 66 ab c1 c8 04 c1 c8 0c 66 ab e2 d8 eb 2b c1 e9 1f 51 68 90 01 04 68 90 01 04 68 90 01 04 e8 90 01 04 89 ca b8 90 01 04 96 81 c6 90 01 04 89 f7 56 eb ab c3 90 00 } //02 00 
		$a_00_2 = {55 52 4c 4f 70 65 6e 53 74 72 65 61 6d 41 } //00 00  URLOpenStreamA
	condition:
		any of ($a_*)
 
}