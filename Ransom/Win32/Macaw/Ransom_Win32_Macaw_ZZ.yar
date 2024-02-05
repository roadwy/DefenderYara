
rule Ransom_Win32_Macaw_ZZ{
	meta:
		description = "Ransom:Win32/Macaw.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //64 00 
		$a_01_1 = {8b 4c 24 04 56 8b f0 c1 e8 02 83 e6 03 85 c0 74 0f 57 8b 3a 89 39 83 c1 04 83 c2 04 48 75 f3 5f 85 f6 74 0d 8b c1 2b d1 8a 0c 02 88 08 40 4e 75 f7 8b 44 24 08 5e c2 04 00 } //00 00 
		$a_00_2 = {5d 04 00 00 e5 c7 04 80 5c 2e 00 00 e6 c7 04 80 00 00 01 00 08 00 18 00 54 72 6f 6a 61 6e 3a 57 69 6e 36 34 2f 52 65 74 69 6e 6a 65 63 74 65 6e 00 00 01 40 05 82 70 00 04 00 67 16 00 00 68 95 29 d2 c8 77 7c 74 33 82 77 f1 00 d4 01 00 01 20 23 a0 3c e5 5d 04 00 00 e6 c7 04 80 5c 27 00 00 e7 c7 04 80 } //00 00 
	condition:
		any of ($a_*)
 
}