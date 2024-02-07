
rule Trojan_AndroidOS_Joker_A{
	meta:
		description = "Trojan:AndroidOS/Joker.A,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {33 2e 31 32 32 2e 31 34 33 2e 32 36 } //01 00  3.122.143.26
		$a_01_1 = {61 70 69 2f 63 6b 77 6b 63 32 3f 69 63 63 3d } //01 00  api/ckwkc2?icc=
		$a_01_2 = {44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //01 00  DexClassLoader
		$a_01_3 = {6c 6f 61 64 43 6c 61 73 73 } //01 00  loadClass
		$a_01_4 = {67 65 74 43 6c 61 73 73 4c 6f 61 64 65 72 } //01 00  getClassLoader
		$a_01_5 = {67 65 74 44 65 63 6c 61 72 65 64 4d 65 74 68 6f 64 } //01 00  getDeclaredMethod
		$a_01_6 = {63 57 64 51 66 45 70 52 67 54 72 59 73 55 68 49 69 4f 79 50 6c 41 6d 53 76 44 77 46 74 47 7a 48 6a 4a 6b 4b 75 4c 61 5a 62 58 65 43 78 56 6e 42 6f 4e 71 4d } //01 00  cWdQfEpRgTrYsUhIiOyPlAmSvDwFtGzHjJkKuLaZbXeCxVnBoNqM
		$a_00_7 = {32 62 61 34 32 61 30 31 34 66 30 63 38 65 39 32 } //00 00  2ba42a014f0c8e92
	condition:
		any of ($a_*)
 
}