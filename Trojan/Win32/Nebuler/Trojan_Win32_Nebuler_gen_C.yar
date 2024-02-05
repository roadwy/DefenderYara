
rule Trojan_Win32_Nebuler_gen_C{
	meta:
		description = "Trojan:Win32/Nebuler.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {74 19 6a 00 6a 00 8d 86 90 01 02 00 00 50 8d 46 0c 50 6a 00 ff d1 f7 d8 1a c0 fe c0 88 86 90 01 02 00 00 f6 d8 1b c0 83 e0 eb 83 c0 15 5f 5e c2 04 00 90 00 } //01 00 
		$a_03_1 = {74 1a 53 56 8b f7 2b f1 8a d8 80 eb 90 01 01 32 da 88 1c 0e 40 41 8a 11 84 d2 75 ee 5e 5b c6 04 38 00 90 00 } //01 00 
		$a_00_2 = {26 76 3d 25 64 26 62 3d 25 64 26 69 64 3d 25 58 26 63 6e 74 3d 25 73 26 71 3d 25 58 } //00 00 
	condition:
		any of ($a_*)
 
}