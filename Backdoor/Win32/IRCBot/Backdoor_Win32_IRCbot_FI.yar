
rule Backdoor_Win32_IRCbot_FI{
	meta:
		description = "Backdoor:Win32/IRCbot.FI,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 70 64 61 74 65 2e 62 71 6c 61 62 2e 63 6f 6d } //01 00 
		$a_01_1 = {76 69 62 6f 74 } //01 00 
		$a_01_2 = {66 6c 6f 6f 64 20 6f 6e 20 25 73 3a 25 73 20 66 6f 72 20 25 73 20 73 65 63 6f 6e 64 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_IRCbot_FI_2{
	meta:
		description = "Backdoor:Win32/IRCbot.FI,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {75 70 64 61 74 65 2e 62 71 6c 61 62 2e 63 6f 6d } //02 00 
		$a_01_1 = {76 69 62 6f 74 } //01 00 
		$a_01_2 = {3a 50 79 4e 65 74 20 62 79 20 76 69 72 61 4c 2c 20 72 65 76 69 73 69 6f 6e 3a 20 25 73 } //01 00 
		$a_01_3 = {3a 55 70 64 61 74 65 54 68 72 65 61 64 3a 20 25 73 } //01 00 
		$a_01_4 = {3a 53 79 6e 54 68 72 65 61 64 3a 20 25 73 } //01 00 
		$a_01_5 = {3a 49 6e 73 74 61 6c 6c 2e 52 65 6d 6f 76 65 28 29 3a 20 25 73 } //00 00 
	condition:
		any of ($a_*)
 
}