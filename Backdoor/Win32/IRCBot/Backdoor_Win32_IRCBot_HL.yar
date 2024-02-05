
rule Backdoor_Win32_IRCBot_HL{
	meta:
		description = "Backdoor:Win32/IRCBot.HL,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 42 53 42 6f 74 00 } //01 00 
		$a_03_1 = {50 4f 4e 47 20 3a 69 72 63 2e 90 02 10 2e 6e 65 74 90 00 } //01 00 
		$a_01_2 = {20 3a 20 75 70 6c 6f 61 64 20 6f 6b } //01 00 
		$a_01_3 = {5c 55 73 65 72 73 5c 41 63 63 6f 75 6e 74 73 2e 63 66 67 } //01 00 
		$a_01_4 = {5c 77 65 62 6d 6f 6e 65 79 5c } //00 00 
		$a_00_5 = {5d 04 00 00 } //90 7d 
	condition:
		any of ($a_*)
 
}