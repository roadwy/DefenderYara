
rule Backdoor_BAT_IRCbot_J{
	meta:
		description = "Backdoor:BAT/IRCbot.J,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 69 72 63 42 6f 74 5c 69 72 63 42 6f 74 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 4c 6f 6c 43 61 63 68 65 2e 70 64 62 } //01 00 
		$a_01_1 = {55 00 73 00 61 00 67 00 65 00 3a 00 20 00 21 00 69 00 73 00 75 00 70 00 20 00 7b 00 75 00 72 00 6c 00 2f 00 69 00 70 00 7d 00 20 00 7b 00 73 00 74 00 72 00 69 00 6e 00 67 00 74 00 6f 00 63 00 68 00 65 00 63 00 6b 00 66 00 6f 00 72 00 2f 00 70 00 6f 00 72 00 74 00 7d 00 } //01 00 
		$a_01_2 = {53 00 65 00 6e 00 64 00 69 00 6e 00 67 00 20 00 7b 00 30 00 7d 00 20 00 66 00 6c 00 6f 00 6f 00 64 00 20 00 74 00 6f 00 20 00 7b 00 31 00 7d 00 20 00 66 00 6f 00 72 00 20 00 7b 00 32 00 7d 00 20 00 73 00 65 00 63 00 6f 00 6e 00 64 00 73 00 20 00 77 00 69 00 74 00 68 00 20 00 7b 00 33 00 7d 00 20 00 74 00 68 00 72 00 65 00 61 00 64 00 73 00 } //01 00 
		$a_01_3 = {62 00 6f 00 74 00 2e 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 65 00 72 00 } //01 00 
		$a_01_4 = {74 00 63 00 70 00 73 00 6d 00 61 00 73 00 68 00 } //00 00 
		$a_00_5 = {80 10 00 } //00 a6 
	condition:
		any of ($a_*)
 
}