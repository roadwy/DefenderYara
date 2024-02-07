
rule BrowserModifier_Win32_Troboxi{
	meta:
		description = "BrowserModifier:Win32/Troboxi,SIGNATURE_TYPE_PEHSTR_EXT,6e 00 6e 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {29 35 35 31 7b 6e 6e 2a 34 33 32 6f 33 34 6e 28 2f 25 24 39 } //05 00  )551{nn*432o34n(/%$9
		$a_01_1 = {68 74 74 70 3a 2f 2f 6b 75 72 73 2e 72 75 2f 69 6e 64 65 78 } //05 00  http://kurs.ru/index
		$a_01_2 = {31 37 36 2e 39 2e 31 35 37 2e 31 34 33 2f 63 6f 75 6e 74 65 72 } //64 00  176.9.157.143/counter
		$a_03_3 = {59 50 6a 01 6a 00 8d 45 d8 50 e8 90 01 02 00 00 59 50 ff 75 a8 ff 15 90 01 02 40 00 ff 75 a8 ff 15 90 01 02 40 00 5f 5e 5b c9 c3 90 00 } //00 00 
		$a_00_4 = {87 10 00 00 17 24 e1 99 de d0 fa e1 d6 29 04 cc 50 59 00 00 5d 04 00 00 82 00 03 00 5c 35 00 00 96 00 03 00 00 00 02 00 15 00 1d 00 53 6f 66 74 77 61 72 65 42 75 6e 64 6c 65 72 3a 57 69 6e 33 32 2f 44 65 61 6c 50 6c 79 00 00 d3 40 03 00 04 82 48 00 04 00 67 16 00 00 8b d2 d2 00 4f 77 83 86 3d 0d c8 96 } //00 ae 
	condition:
		any of ($a_*)
 
}