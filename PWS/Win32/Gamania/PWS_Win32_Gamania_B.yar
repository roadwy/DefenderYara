
rule PWS_Win32_Gamania_B{
	meta:
		description = "PWS:Win32/Gamania.B,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 05 00 "
		
	strings :
		$a_00_0 = {c1 f9 02 78 11 fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //05 00 
		$a_00_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6e 65 74 67 61 6d 65 72 6a 70 2e 63 6f 6d 2f 6a 70 2f 6d 61 69 6c 2e 61 73 70 3f 74 6f 6d 61 69 6c 3d 31 36 33 40 31 36 33 2e 63 6f 6d 26 6d 61 69 6c 62 6f 64 79 3d 00 } //01 00 
		$a_01_2 = {47 45 54 20 00 00 00 00 ff ff ff ff 0b 00 00 00 20 48 54 54 50 2f 31 2e 30 0d 0a 00 ff } //01 00 
		$a_01_3 = {0d 0a 00 00 ff ff ff ff 18 00 00 00 41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e 0d 0a 00 00 00 00 ff ff ff ff 40 } //01 00 
		$a_00_4 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //02 00  SetWindowsHookExA
		$a_00_5 = {67 61 6d 65 3a 6a 70 72 6f 0d 0a 73 65 72 76 65 72 3a } //01 00  慧敭樺牰൯猊牥敶㩲
		$a_00_6 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //00 00  SOFTWARE\Borland\Delphi\RTL
	condition:
		any of ($a_*)
 
}