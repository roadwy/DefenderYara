
rule PWS_Win32_OnLineGames_FA{
	meta:
		description = "PWS:Win32/OnLineGames.FA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b d2 8b c0 90 90 8b d2 } //02 00 
		$a_03_1 = {8b 55 0c 8d 4d fc 51 57 52 53 56 ff 15 90 01 02 40 00 85 c0 0f 84 90 01 01 00 00 00 b0 45 b1 61 90 00 } //01 00 
		$a_01_2 = {b0 20 b1 73 88 45 ea } //00 00 
	condition:
		any of ($a_*)
 
}