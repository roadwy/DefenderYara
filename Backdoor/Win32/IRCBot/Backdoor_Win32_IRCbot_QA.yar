
rule Backdoor_Win32_IRCbot_QA{
	meta:
		description = "Backdoor:Win32/IRCbot.QA,SIGNATURE_TYPE_PEHSTR,24 00 23 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {65 75 2e 75 6e 64 65 72 6e 65 74 2e 6f 72 67 } //0a 00 
		$a_01_1 = {4e 49 43 4b 20 62 6c 61 } //0a 00 
		$a_01_2 = {53 6d 61 6c 6c 20 49 52 43 20 42 6f 74 } //05 00 
		$a_01_3 = {43 6c 69 65 6e 74 20 68 6f 6f 6b } //01 00 
		$a_01_4 = {6a 6f 69 6e 20 25 73 } //00 00 
	condition:
		any of ($a_*)
 
}