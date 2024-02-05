
rule PWS_Win32_OnLineGames_AK{
	meta:
		description = "PWS:Win32/OnLineGames.AK,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f 84 91 00 00 00 6a 02 6a 00 68 4a ff ff ff 53 e8 } //01 00 
		$a_03_1 = {8b c8 49 85 c9 72 1e 41 a1 90 01 04 8b 15 90 01 04 8a 18 80 c3 90 01 01 80 f3 90 01 01 80 eb 90 01 01 88 1a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}