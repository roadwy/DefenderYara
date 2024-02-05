
rule Backdoor_Win32_IRCbot_EV{
	meta:
		description = "Backdoor:Win32/IRCbot.EV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 46 08 88 00 00 00 c7 46 0c 84 00 00 00 } //01 00 
		$a_01_1 = {8b 44 24 04 8b 08 6a 00 ff d1 b8 01 00 00 00 c2 04 00 } //01 00 
		$a_01_2 = {83 cb 01 c6 44 24 2a 50 c6 44 24 2b 49 c6 44 24 2c 4e c6 44 24 2d 47 c6 44 24 2e 00 ff d6 83 c4 08 85 c0 0f 85 } //00 00 
	condition:
		any of ($a_*)
 
}