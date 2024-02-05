
rule Ransom_Win32_BlackMatter_ZX{
	meta:
		description = "Ransom:Win32/BlackMatter.ZX,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //64 00 
		$a_01_1 = {b8 41 42 43 44 ab b8 45 46 47 48 ab b8 49 4a 4b 4c ab b8 4d 4e 4f 50 ab b8 51 52 53 54 ab b8 55 56 57 58 ab b8 59 5a 61 62 ab b8 63 64 65 66 ab b8 67 68 69 6a ab b8 6b 6c 6d 6e ab b8 6f 70 71 72 ab b8 73 74 75 76 ab b8 77 78 79 7a ab b8 30 31 32 33 ab b8 34 35 36 37 ab b8 38 39 2b 2f ab } //00 00 
		$a_00_2 = {5d 04 00 00 20 a4 04 80 5c 32 00 00 21 a4 04 80 00 00 01 00 08 00 1c 00 54 72 6f 6a 61 6e 3a 41 6e 64 72 6f 69 64 4f 53 2f 4a 6f 6b 65 72 2e 47 21 4d 54 42 00 00 01 40 05 82 70 00 04 00 67 16 00 00 79 d4 34 33 4f 59 30 98 dc 89 69 6b 9c b0 80 00 01 20 65 26 5e 0e 5d 04 00 00 21 a4 04 80 5c 25 00 00 } //22 a4 
	condition:
		any of ($a_*)
 
}