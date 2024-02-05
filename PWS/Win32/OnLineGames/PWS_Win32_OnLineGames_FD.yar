
rule PWS_Win32_OnLineGames_FD{
	meta:
		description = "PWS:Win32/OnLineGames.FD,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 06 b8 c6 46 05 ff c6 46 06 e0 c6 46 07 00 8d 45 fc 50 6a 08 } //01 00 
		$a_03_1 = {8a 5c 10 ff 80 eb 7f 8d 45 f8 8b d3 e8 90 01 02 ff ff 8b 55 f8 8b c7 e8 90 01 02 ff ff ff 45 fc 4e 75 d9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}