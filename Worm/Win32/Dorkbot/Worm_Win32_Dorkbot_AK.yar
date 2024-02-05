
rule Worm_Win32_Dorkbot_AK{
	meta:
		description = "Worm:Win32/Dorkbot.AK,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 08 50 ff 51 08 8b 45 90 01 01 3b c3 5b 74 06 8b 08 50 ff 51 08 c9 c3 90 00 } //01 00 
		$a_03_1 = {6a 32 ff d6 6a 00 6a 09 53 ff 75 90 01 01 ff d7 6a 32 ff d6 6a 02 6a 10 e8 90 01 04 59 59 6a 32 ff d6 6a 00 6a 0d 53 ff 75 90 01 01 ff d7 6a 32 ff d6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}