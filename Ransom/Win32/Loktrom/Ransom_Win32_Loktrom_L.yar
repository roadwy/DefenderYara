
rule Ransom_Win32_Loktrom_L{
	meta:
		description = "Ransom:Win32/Loktrom.L,SIGNATURE_TYPE_PEHSTR_EXT,ffffff8c 00 ffffff87 00 07 00 00 64 00 "
		
	strings :
		$a_01_0 = {83 c0 09 89 44 24 10 8b 44 24 04 05 f1 00 00 00 89 44 24 14 8b 44 24 08 83 e8 16 89 44 24 18 8b 44 24 0c 83 e8 6e 89 44 24 1c } //0f 00 
		$a_01_1 = {31 29 20 cd e0 e9 e4 e8 f2 e5 20 e1 eb e8 e6 e0 e9 f8 e8 e9 20 f2 e5 f0 ec e8 ed e0 eb 20 ee ef } //0f 00 
		$a_01_2 = {ee e9 20 f1 e2 ff e7 e8 2c 20 ed e0 ef f0 e8 ec e5 f0 20 49 42 4f 58 2c 20 32 34 4e 6f 6e 53 74 6f 70 2c } //0f 00 
		$a_01_3 = {f2 20 f2 e5 f0 ec e8 ed e0 eb e0 29 20 2d 2d 3e 20 22 57 65 62 4d 6f 6e 65 79 22 } //0f 00 
		$a_01_4 = {cb ce ca c8 d0 ce c2 ca c8 20 57 49 4e 44 4f 57 53 20 cd c5 ce c1 d5 ce c4 c8 cc ce 20 ce cf cb } //0a 00 
		$a_01_5 = {61 6c 66 61 61 62 61 62 61 67 61 6c 61 6d 61 67 61 } //0a 00  alfaababagalamaga
		$a_01_6 = {4b 4c 42 54 42 54 4e 42 49 54 42 54 4e 31 5f 42 49 54 4d 41 50 } //00 00  KLBTBTNBITBTN1_BITMAP
		$a_00_7 = {80 10 00 00 19 bb a1 03 02 9f 39 19 1f cf 48 34 00 10 00 80 80 10 00 00 f0 } //60 1d 
	condition:
		any of ($a_*)
 
}