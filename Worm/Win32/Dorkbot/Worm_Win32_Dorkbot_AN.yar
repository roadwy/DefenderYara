
rule Worm_Win32_Dorkbot_AN{
	meta:
		description = "Worm:Win32/Dorkbot.AN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 08 50 ff 51 08 8b 45 90 01 01 90 03 02 04 3b c3 3b c7 5f 5e 5b 74 06 8b 08 50 ff 51 08 c9 c3 90 00 } //01 00 
		$a_03_1 = {8b 50 04 8b 7d 90 01 01 0f b6 f1 8a 14 32 32 10 32 d1 fe c1 88 14 3e 3a 48 01 72 e6 90 00 } //01 00 
		$a_03_2 = {6a 07 68 00 08 00 00 ff d0 8d 45 90 01 01 50 90 03 01 03 6a 33 db 53 90 02 01 90 04 01 02 53 56 e8 90 01 04 8d 45 90 01 01 50 e8 90 00 } //00 00 
		$a_00_3 = {80 10 } //00 00 
	condition:
		any of ($a_*)
 
}