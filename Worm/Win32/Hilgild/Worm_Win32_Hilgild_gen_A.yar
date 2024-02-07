
rule Worm_Win32_Hilgild_gen_A{
	meta:
		description = "Worm:Win32/Hilgild!gen.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 04 3e 8a c8 8a d0 c0 f9 03 80 e2 0e 80 e1 0e c0 e2 03 0a ca 24 81 0a c8 88 0c 3e 46 3b f5 7c df } //02 00 
		$a_03_1 = {68 3f 77 1b 00 ff 90 01 03 40 00 e9 90 00 } //01 00 
		$a_01_2 = {47 48 49 5f 42 41 54 00 } //01 00  䡇彉䅂T
		$a_01_3 = {7e 68 75 6d 62 73 2e 74 6d 70 00 } //01 00 
		$a_01_4 = {68 45 4c 6c 4f 20 4d 79 62 41 62 59 21 00 } //01 00  䕨汌⁏祍䅢奢!
		$a_01_5 = {43 4c 56 45 52 3d 00 } //00 00 
	condition:
		any of ($a_*)
 
}