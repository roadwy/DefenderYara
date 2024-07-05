
rule Ransom_Win32_BlackCat_ZA_MTB{
	meta:
		description = "Ransom:Win32/BlackCat.ZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc9 00 ffffffc9 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //64 00 
		$a_01_1 = {89 d3 89 c8 31 d2 f7 f6 8b 45 f0 0f b6 04 10 89 da 30 04 0b 41 39 cf } //64 00 
		$a_03_2 = {8b 0e 8a 15 90 01 04 88 14 01 ff 46 08 a2 90 00 } //00 00 
		$a_00_3 = {5d 04 00 00 2f 81 05 80 5c 31 00 00 30 81 05 80 00 00 01 00 32 00 1b 00 52 61 6e 73 6f 6d 3a 57 69 6e 33 32 2f 4c 6f 63 6b 62 69 74 2e 48 41 21 4d 54 42 00 00 1e 40 05 82 70 00 04 00 67 16 00 00 f6 37 a6 0d d2 e2 00 dc 13 c1 82 f3 00 66 02 00 01 20 b4 77 dd b4 67 16 00 00 ea 7c 18 17 4a b3 6a c2 a2 65 1f 7a 00 00 69 00 01 20 5c 23 24 e2 67 16 00 00 76 af d6 2d d2 e2 00 dc 16 45 07 85 00 66 02 00 01 20 2c 32 1b 46 67 16 00 00 88 58 45 39 c1 0a 59 35 ed 27 46 7e 00 f4 68 00 01 20 bf c0 77 0b 67 16 00 00 de 63 0c 3a 57 5e 4c be e1 d1 fe 38 00 6c 0a 00 01 20 68 40 0b d1 67 16 00 00 4b 5c 87 59 d2 } //e2 00 
	condition:
		any of ($a_*)
 
}