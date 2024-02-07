
rule Worm_Win32_Dutan_A{
	meta:
		description = "Worm:Win32/Dutan.A,SIGNATURE_TYPE_PEHSTR_EXT,41 00 3c 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //0a 00  SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {5c 52 75 6e 00 00 00 ff ff ff ff 14 00 00 00 4d 69 63 72 6f 73 6f 66 74 20 4f 66 66 69 63 65 54 6f 6f 6c 00 00 00 00 55 8b ec } //0a 00 
		$a_00_2 = {ff ff ff ff 0b 00 00 00 61 75 74 6f 72 75 6e 2e 69 6e 66 } //0a 00 
		$a_00_3 = {73 76 63 68 6f 73 74 73 2e 65 78 65 00 00 00 00 63 73 72 73 73 73 2e 65 78 65 00 00 ff ff ff ff 0d 00 00 00 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 00 00 00 ff ff ff ff 01 00 00 00 5c 00 00 00 ff ff ff ff 16 00 00 00 43 3a 5c 44 55 54 4f 41 4e 39 37 5c 44 55 54 4f 41 4e 2e 45 58 45 00 00 } //14 00 
		$a_00_4 = {2e 65 78 65 00 00 00 00 2e 78 6c 73 00 00 00 00 55 8b ec } //05 00 
		$a_01_5 = {47 65 74 44 72 69 76 65 54 79 70 65 41 } //00 00  GetDriveTypeA
	condition:
		any of ($a_*)
 
}