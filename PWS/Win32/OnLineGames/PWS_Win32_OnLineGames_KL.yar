
rule PWS_Win32_OnLineGames_KL{
	meta:
		description = "PWS:Win32/OnLineGames.KL,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 50 ff 83 e8 02 88 51 ff 8a 50 02 88 11 8d 14 06 83 c1 02 85 d2 7f e8 } //01 00 
		$a_00_1 = {00 65 39 25 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}