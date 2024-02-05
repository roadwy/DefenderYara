
rule Ransom_Win32_BlackMatter_ZY{
	meta:
		description = "Ransom:Win32/BlackMatter.ZY,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //64 00 
		$a_01_1 = {33 c0 8b 55 0c 8b 75 08 66 ad 66 83 f8 41 72 0a 66 83 f8 5a 77 04 66 83 c8 20 80 c6 61 80 ee 61 c1 ca 0d 03 d0 85 c0 75 df } //00 00 
		$a_00_2 = {5d 04 00 00 1f a4 04 80 5c 31 00 00 20 a4 04 80 00 00 01 00 32 00 1b 00 52 61 6e 73 6f 6d 3a 57 69 6e 33 32 2f 42 6c 61 63 6b 4d 61 74 74 65 72 2e 5a 58 00 00 01 40 05 82 70 00 04 00 78 7d 00 00 65 00 65 00 02 00 00 01 00 0a 00 f1 d5 00 fa 4c 62 cc f4 0f 0b 64 00 60 01 b8 41 42 43 44 ab b8 45 46 47 } //48 ab 
	condition:
		any of ($a_*)
 
}