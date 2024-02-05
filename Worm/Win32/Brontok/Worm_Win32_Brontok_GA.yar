
rule Worm_Win32_Brontok_GA{
	meta:
		description = "Worm:Win32/Brontok.GA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0a 7f 00 04 00 04 68 ff 04 58 ff 0a 80 00 08 00 04 58 ff fb e9 48 ff 55 70 7a ff 36 04 00 68 ff 58 ff 04 46 ff 10 f8 06 08 00 6b 46 ff f4 ff c6 1c 8e 00 6b 7a ff f4 02 c1 f4 00 c6 1c 6b 00 04 40 ff f4 03 1b e7 00 10 18 07 08 00 f5 00 00 00 00 3e 40 ff 46 68 ff 0a 29 00 08 00 74 38 ff 35 68 ff 1e 8e 00 04 40 ff f4 03 1b e8 00 10 18 07 08 00 f5 00 00 00 00 3e 40 ff 46 68 ff } //01 00 
		$a_00_1 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c 00 00 00 00 4d 65 74 68 43 61 6c 6c 45 6e 67 69 6e 65 } //00 00 
	condition:
		any of ($a_*)
 
}