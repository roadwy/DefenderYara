
rule PWS_Win32_OnLineGames_HM{
	meta:
		description = "PWS:Win32/OnLineGames.HM,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 02 00 "
		
	strings :
		$a_00_0 = {44 00 4e 00 46 00 2e 00 65 00 78 00 65 00 } //02 00 
		$a_00_1 = {48 00 4f 00 4f 00 4b 00 } //02 00 
		$a_02_2 = {64 00 65 00 6c 00 90 02 0b 69 00 66 00 20 00 65 00 78 00 69 00 73 00 74 00 90 02 0b 67 00 6f 00 74 00 6f 00 90 00 } //01 00 
		$a_00_3 = {26 70 61 73 73 77 6f 72 64 32 3d } //01 00 
		$a_00_4 = {26 6d 6f 6e 65 79 3d } //01 00 
		$a_00_5 = {26 6c 65 76 65 6c 3d } //00 00 
	condition:
		any of ($a_*)
 
}