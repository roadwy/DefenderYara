
rule Trojan_Win32_Leeson_A_dha{
	meta:
		description = "Trojan:Win32/Leeson.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 24 24 24 25 73 26 26 26 25 73 26 26 26 25 73 26 26 26 25 64 26 26 26 25 6c 64 26 26 26 25 73 } //01 00  f$$$%s&&&%s&&&%s&&&%d&&&%ld&&&%s
		$a_01_1 = {4d 72 4f 6d 41 6b 71 74 6f 32 36 72 51 6b 59 37 6e 5a 4b 64 36 67 3d 3d } //01 00  MrOmAkqto26rQkY7nZKd6g==
		$a_01_2 = {62 24 24 24 25 73 26 26 26 25 64 26 26 26 25 64 26 26 26 } //01 00  b$$$%s&&&%d&&&%d&&&
		$a_00_3 = {77 00 28 00 5b 00 61 00 2d 00 7a 00 41 00 2d 00 5a 00 5d 00 2b 00 29 00 } //00 00  w([a-zA-Z]+)
	condition:
		any of ($a_*)
 
}