
rule PWS_Win32_OnLineGames_AM{
	meta:
		description = "PWS:Win32/OnLineGames.AM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {5e 5b 74 0a e8 90 01 04 e8 90 01 04 68 90 01 02 40 00 ff 15 90 01 02 40 00 68 90 90 5f 01 00 ff 15 90 01 02 40 00 90 00 } //01 00 
		$a_03_1 = {6a 0a 68 c8 00 00 00 56 ff 15 90 01 02 40 00 85 c0 74 29 50 56 ff 15 90 01 02 40 00 90 00 } //02 00 
		$a_03_2 = {6a 64 ff d6 e8 90 01 02 ff ff 6a 64 ff d6 e8 90 01 02 ff ff 6a 64 ff d6 eb a6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule PWS_Win32_OnLineGames_AM_2{
	meta:
		description = "PWS:Win32/OnLineGames.AM,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 65 72 76 65 72 3d 25 73 26 61 63 63 6f 75 6e 74 3d 25 73 26 70 61 73 73 77 6f 72 64 31 3d 25 73 } //01 00 
		$a_00_1 = {26 6c 65 76 65 6c 73 3d 25 73 26 63 61 73 68 3d 25 73 26 6e 61 6d 65 3d 25 73 26 73 70 65 63 69 61 6c 53 69 67 6e 3d 25 73 26 } //01 00 
		$a_00_2 = {26 50 72 6f 74 50 61 73 73 3d 25 73 26 56 65 72 69 66 79 3d 25 73 } //01 00 
		$a_02_3 = {68 74 74 70 3a 2f 2f 90 02 20 77 6f 77 2f 70 6f 73 74 2e 61 73 70 90 00 } //01 00 
		$a_00_4 = {3f 61 63 74 3d 67 65 74 6d 62 6f 6b 26 61 63 63 6f 75 6e 74 3d 25 73 26 6d 62 3d 25 73 } //00 00 
	condition:
		any of ($a_*)
 
}