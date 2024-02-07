
rule Trojan_Win32_Ramnit_F_{
	meta:
		description = "Trojan:Win32/Ramnit.F!!Ramnit.gen!F,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {b9 1d f3 01 00 f7 f1 8b c8 b8 a7 41 00 00 f7 e2 8b d1 8b c8 b8 14 0b 00 00 f7 e2 2b c8 33 d2 8b c1 8b d9 f7 75 } //01 00 
		$a_00_1 = {8b 4d 0c 8b 7d 08 8b 75 10 ba 00 00 00 00 0b d2 75 04 8b 55 14 4a 8a 1c 32 32 1f 88 1f 47 4a e2 ed } //02 00 
		$a_01_2 = {66 42 31 6f 4e 35 66 72 47 71 66 00 } //02 00  䉦漱㕎牦煇f
		$a_01_3 = {66 45 34 68 4e 79 31 4f 00 } //00 00 
	condition:
		any of ($a_*)
 
}