
rule Ransom_Win32_BlackMatter_ZZ{
	meta:
		description = "Ransom:Win32/BlackMatter.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //64 00 
		$a_01_1 = {33 c0 8b 55 0c 8b 75 08 ac 80 c6 61 80 ee 61 c1 ca 0d 03 d0 85 c0 75 f0 8b c2 } //00 00 
		$a_00_2 = {5d 04 00 00 1e a4 04 80 5c 31 00 00 1f a4 04 80 00 00 01 00 32 00 1b 00 52 61 6e 73 6f 6d 3a 57 69 6e 33 32 2f 42 6c 61 63 6b 4d 61 74 74 65 72 2e 5a 59 00 00 01 40 05 82 70 00 04 00 78 46 00 00 65 00 65 00 02 00 00 01 00 0a 00 f1 d5 00 fa 4c 62 cc f4 0f 0b 64 00 29 01 33 c0 8b 55 0c 8b 75 08 66 ad } //66 83 
	condition:
		any of ($a_*)
 
}