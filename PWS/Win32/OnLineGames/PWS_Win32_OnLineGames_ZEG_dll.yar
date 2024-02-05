
rule PWS_Win32_OnLineGames_ZEG_dll{
	meta:
		description = "PWS:Win32/OnLineGames.ZEG!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 44 24 14 51 c6 44 24 15 51 c6 44 24 16 4c c6 44 24 17 6f c6 44 24 18 67 c6 44 24 19 69 c6 44 24 1a 6e c6 44 24 1b 2e 88 5c 24 1c } //01 00 
		$a_01_1 = {5c 64 6e 66 5c 62 69 65 73 68 61 77 6f 2e 65 78 65 } //01 00 
		$a_01_2 = {5c 73 79 73 74 65 6d 33 32 5c 77 61 68 61 68 61 2e 69 6d 65 } //01 00 
		$a_01_3 = {c4 e3 ba c3 c9 b1 b6 be c8 ed bc fe 00 } //01 00 
		$a_03_4 = {26 71 75 3d 90 01 04 26 70 61 73 73 3d 00 00 3f 75 73 65 72 6e 61 6d 65 3d 90 01 0a 6c 69 6e 2e 61 73 70 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}