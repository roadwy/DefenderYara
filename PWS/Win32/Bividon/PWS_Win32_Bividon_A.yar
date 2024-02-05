
rule PWS_Win32_Bividon_A{
	meta:
		description = "PWS:Win32/Bividon.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 05 00 00 03 00 "
		
	strings :
		$a_03_0 = {89 45 ec 6a 40 68 00 30 00 00 8d 45 e8 8b d6 e8 90 01 03 ff 8b 45 e8 e8 90 01 03 ff 40 50 6a 00 53 ff d7 8b f8 8d 45 f4 50 8d 45 e4 8b d6 e8 90 01 03 ff 8b 45 e4 e8 90 01 03 ff 40 50 56 57 53 ff 55 ec 90 00 } //01 00 
		$a_01_1 = {66 81 3f 4d 5a 75 11 8d 46 3c 8b 18 03 de 81 3b 50 45 00 00 74 02 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 00 00 56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00 
		$a_01_3 = {56 65 72 73 69 6f 6e 5c 52 75 6e 00 00 00 55 8b } //01 00 
		$a_01_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 00 4c 6f 61 64 4c 69 } //00 00 
	condition:
		any of ($a_*)
 
}
rule PWS_Win32_Bividon_A_2{
	meta:
		description = "PWS:Win32/Bividon.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 55 fc 8a 54 1a ff 80 f2 e9 88 54 18 ff 43 4e 75 e6 } //01 00 
		$a_01_1 = {bb 01 00 00 00 8d 45 ec 50 b9 01 00 00 00 8b d3 8b c7 } //01 00 
		$a_01_2 = {77 69 6e 6b 00 } //01 00 
		$a_01_3 = {80 38 01 75 0c 68 00 ba db 00 e8 } //01 00 
		$a_01_4 = {2d 93 08 00 00 74 0c 2d 95 01 00 00 74 36 } //03 00 
		$a_01_5 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b } //00 00 
	condition:
		any of ($a_*)
 
}