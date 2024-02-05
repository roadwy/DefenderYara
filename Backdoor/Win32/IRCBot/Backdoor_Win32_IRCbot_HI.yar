
rule Backdoor_Win32_IRCbot_HI{
	meta:
		description = "Backdoor:Win32/IRCbot.HI,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 73 6c 6f 77 70 6f 73 74 00 73 6c 6f 77 6c 6f 72 69 73 00 } //01 00 
		$a_00_1 = {66 6c 6f 6f 64 2e 61 6e 6f 70 65 } //01 00 
		$a_00_2 = {25 73 5c 49 25 6c 69 2e 62 61 74 } //01 00 
		$a_00_3 = {61 6a 61 78 20 49 52 43 20 43 6c 69 65 6e 74 } //01 00 
		$a_00_4 = {2f 4d 4f 54 44 20 63 6f 6d 6d 61 6e 64 } //00 00 
	condition:
		any of ($a_*)
 
}