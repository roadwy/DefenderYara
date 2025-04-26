
rule Trojan_Win32_Lummac_SC{
	meta:
		description = "Trojan:Win32/Lummac.SC,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {b0 40 c3 b0 3f c3 89 c8 04 d0 3c 09 77 06 80 c1 04 89 c8 c3 } //10
		$a_03_1 = {b0 40 c3 b0 3f c3 80 f9 30 72 ?? 80 f9 39 77 06 80 c1 04 89 c8 c3 } //10
		$a_01_2 = {8b 4c 24 04 8b 14 24 31 ca f7 d2 21 ca 29 d0 } //10
		$a_01_3 = {89 f1 c1 e9 0c 80 c9 e0 88 08 89 f1 c1 e9 06 80 e1 3f 80 c9 80 88 48 01 80 e2 3f } //10
		$a_01_4 = {02 0f b7 16 83 c6 02 66 85 d2 75 ef 66 c7 00 00 00 0f b7 11 } //5
		$a_01_5 = {0c 0f b7 4c 24 04 66 89 0f 83 c7 02 39 f7 73 0c 01 c3 39 eb } //5
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5) >=10
 
}