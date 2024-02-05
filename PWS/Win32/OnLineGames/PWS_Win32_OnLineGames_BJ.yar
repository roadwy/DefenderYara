
rule PWS_Win32_OnLineGames_BJ{
	meta:
		description = "PWS:Win32/OnLineGames.BJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {c6 07 61 c6 47 90 01 01 63 c6 47 90 01 01 74 c6 47 90 01 01 3d c6 47 90 01 01 67 c6 47 90 01 01 65 c6 47 90 01 01 74 c6 47 90 01 01 70 c6 47 90 01 01 6f c6 47 90 01 01 73 c6 47 90 01 01 26 90 00 } //01 00 
		$a_01_1 = {b0 42 aa b0 6f aa b0 2e aa b0 65 aa b0 78 aa b0 65 } //01 00 
		$a_01_2 = {b0 6d aa b0 69 aa b0 62 aa b0 61 aa b0 6f aa b0 2e aa b0 61 aa b0 73 aa b0 70 } //01 00 
		$a_00_3 = {b0 75 aa b0 6e aa b0 74 aa b0 3d aa b0 25 aa b0 73 } //01 00 
		$a_00_4 = {b0 2d aa b0 31 aa b0 32 aa aa b0 37 aa b0 2d aa b0 4e aa b0 45 aa b0 57 } //00 00 
	condition:
		any of ($a_*)
 
}