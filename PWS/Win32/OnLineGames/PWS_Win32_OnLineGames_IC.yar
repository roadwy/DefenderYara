
rule PWS_Win32_OnLineGames_IC{
	meta:
		description = "PWS:Win32/OnLineGames.IC,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {c6 07 e8 2b c7 83 e8 05 89 47 01 8a 45 0b 3c 68 88 47 05 74 0e 3c a3 } //01 00 
		$a_01_1 = {25 73 3f 61 63 74 3d 67 65 74 70 6f 73 26 64 31 30 } //01 00 
		$a_01_2 = {25 73 5c 64 6c 6c 63 61 63 68 65 5c 25 73 5f 25 64 2e 6a 70 67 } //00 00 
	condition:
		any of ($a_*)
 
}