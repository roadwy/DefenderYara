
rule Ransom_Win32_Ryuk_ZZ{
	meta:
		description = "Ransom:Win32/Ryuk.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //64 00 
		$a_03_1 = {55 8b ec 83 ec 90 01 01 53 90 03 06 04 33 c9 56 57 89 4d 56 57 c7 45 90 02 20 99 f7 7d 0c 8b 90 01 02 90 03 01 01 89 8b 90 01 02 90 03 01 01 89 8b 90 02 0a 88 45 ff 60 33 c0 8a 45 ff 33 c9 8b 4d f4 d2 c8 88 45 ff 61 8b 90 00 } //00 00 
		$a_00_2 = {5d 04 00 00 9e 90 04 80 5c 30 00 00 a0 90 04 80 00 00 01 00 08 00 1a 00 54 72 6f 6a 61 6e 3a 41 6e 64 72 6f 69 64 4f 53 2f 57 6f 6c 66 52 41 54 2e 41 00 00 01 40 05 82 70 00 04 00 be 0e 02 00 0d 00 0d 00 0e 00 00 01 00 0e 00 53 63 72 65 65 6e 52 65 63 6f 72 64 65 72 01 00 0a 00 54 68 72 65 61 64 20 } //52 65 
	condition:
		any of ($a_*)
 
}