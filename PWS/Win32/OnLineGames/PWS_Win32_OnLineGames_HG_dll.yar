
rule PWS_Win32_OnLineGames_HG_dll{
	meta:
		description = "PWS:Win32/OnLineGames.HG!dll,SIGNATURE_TYPE_PEHSTR_EXT,08 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {68 66 30 30 32 31 2e 64 6c 6c 00 } //02 00 
		$a_01_1 = {73 65 74 68 6f 6f 6b 65 20 3d 20 25 30 38 78 00 } //02 00 
		$a_01_2 = {2e 5c 44 4e 46 2e 63 66 67 00 } //01 00 
		$a_01_3 = {26 73 65 63 75 6c 6f 67 69 6e 3d 00 } //01 00 
		$a_01_4 = {26 73 74 72 50 61 73 73 77 6f 72 64 3d 00 } //00 00 
	condition:
		any of ($a_*)
 
}