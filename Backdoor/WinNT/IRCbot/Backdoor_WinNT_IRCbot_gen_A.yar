
rule Backdoor_WinNT_IRCbot_gen_A{
	meta:
		description = "Backdoor:WinNT/IRCbot.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {7e 0c 8a 54 24 0c 30 14 31 41 3b c8 7c f4 } //01 00 
		$a_01_1 = {85 c0 74 07 b8 34 00 00 c0 eb 2e 50 } //01 00 
		$a_01_2 = {59 59 74 21 8b 45 fc be 22 00 00 c0 } //01 00 
		$a_09_3 = {73 79 73 74 65 6d 2e 65 78 65 00 } //01 00 
	condition:
		any of ($a_*)
 
}