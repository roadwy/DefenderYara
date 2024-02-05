
rule Backdoor_Win32_IRCbot_AE{
	meta:
		description = "Backdoor:Win32/IRCbot.AE,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c1 99 f7 3d 90 01 03 00 8a 82 90 01 03 00 8a 14 90 01 01 32 d0 90 00 } //01 00 
		$a_01_1 = {64 a1 30 00 00 00 8b 40 0c 8b 40 14 } //01 00 
		$a_03_2 = {6a 40 68 00 30 00 00 8b 90 01 01 50 8b 90 01 01 34 90 00 } //01 00 
		$a_03_3 = {8b 48 34 51 90 01 01 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}