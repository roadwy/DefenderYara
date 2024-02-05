
rule Worm_Win32_IRCbot_K{
	meta:
		description = "Worm:Win32/IRCbot.K,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00 
		$a_00_1 = {25 73 73 2e 6c 6e 6b } //01 00 
		$a_00_2 = {50 52 49 56 4d 53 47 } //01 00 
		$a_00_3 = {4a 4f 49 4e } //01 00 
		$a_00_4 = {4e 49 43 4b } //01 00 
		$a_00_5 = {83 f8 02 75 2c 8b 55 fc 0f be 02 83 c8 20 83 f8 61 74 1e 8b 4d fc 0f be 11 83 ca 20 83 fa 62 74 10 8b 45 08 50 8b 4d fc 51 } //01 00 
		$a_02_6 = {83 fa 6a 7d 25 6a 0c 6a 32 0f b6 85 37 fe ff ff 6b c0 64 05 90 01 04 50 8d 8d 38 fe ff ff 51 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}