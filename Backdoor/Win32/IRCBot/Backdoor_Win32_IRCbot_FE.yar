
rule Backdoor_Win32_IRCbot_FE{
	meta:
		description = "Backdoor:Win32/IRCbot.FE,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {5a 79 6d 61 20 47 72 6f 75 70 } //01 00 
		$a_01_1 = {5b 61 75 74 6f 72 75 6e 5d 0d 0a 73 68 65 6c 6c 65 78 65 63 75 74 65 3d 25 73 } //01 00 
		$a_01_2 = {50 52 49 56 4d 53 47 20 25 73 20 3a 25 73 25 73 25 73 25 73 25 73 25 69 } //01 00 
		$a_01_3 = {3a 21 75 64 70 66 6c 6f 6f 64 } //01 00 
		$a_01_4 = {3a 21 72 65 63 6f 6e } //01 00 
		$a_01_5 = {3a 21 75 70 64 61 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}