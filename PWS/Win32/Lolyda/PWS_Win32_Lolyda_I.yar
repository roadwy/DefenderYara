
rule PWS_Win32_Lolyda_I{
	meta:
		description = "PWS:Win32/Lolyda.I,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {0b c0 74 4c 33 d2 eb 40 8b 7d f4 03 fa 81 3f 23 fe 4e f7 75 30 83 7f 08 00 74 2a 81 7f 0c 84 14 1a af } //01 00 
		$a_00_1 = {3f 73 65 72 76 65 72 3d 25 73 26 67 61 6d 65 69 64 3d 25 73 26 70 61 73 73 3d 25 73 26 70 69 6e 3d 25 73 26 77 75 70 69 6e 3d 25 73 26 72 6f 6c 65 3d 25 73 26 65 71 75 3d } //01 00  ?server=%s&gameid=%s&pass=%s&pin=%s&wupin=%s&role=%s&equ=
		$a_01_2 = {46 6f 72 74 68 67 6f 6e 65 72 } //01 00  Forthgoner
		$a_01_3 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 64 00 65 00 76 00 48 00 42 00 4b 00 65 00 72 00 6e 00 65 00 6c 00 } //00 00  \Device\devHBKernel
	condition:
		any of ($a_*)
 
}