
rule Backdoor_Win32_IRCBot_TA{
	meta:
		description = "Backdoor:Win32/IRCBot.TA,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 4e 53 49 49 20 52 4b 69 74 } //01 00 
		$a_01_1 = {70 68 70 4d 79 41 64 6d 69 6e 2f 73 63 72 69 70 74 73 2f 73 65 74 75 70 2e 70 68 70 } //01 00 
		$a_01_2 = {25 33 41 31 25 33 41 25 37 42 69 25 33 41 30 25 33 42 4f 25 33 41 31 30 25 33 41 25 32 32 50 4d 41 5f 43 6f 6e 66 69 67 } //01 00 
		$a_00_3 = {62 69 7a 2f 73 2e 69 63 6f } //00 00 
		$a_00_4 = {78 86 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_IRCBot_TA_2{
	meta:
		description = "Backdoor:Win32/IRCBot.TA,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 64 64 6f 73 5d 3a } //01 00 
		$a_01_1 = {53 6c 6f 77 6c 6f 72 69 73 20 61 74 74 61 63 6b 28 29 } //01 00 
		$a_01_2 = {5b 53 55 50 45 52 53 59 4e 5d 20 44 6f 6e 65 20 77 69 74 68 20 66 6c 6f 6f 64 } //01 00 
		$a_01_3 = {5b 55 53 42 5d 2d 2d 3e 5b 25 73 5d } //01 00 
		$a_01_4 = {5b 4c 41 4e 5d 2d 2d 3e 5b 25 73 5d } //05 00 
		$a_03_5 = {0f be 00 83 e8 4e 99 b9 1a 00 00 00 f7 f9 83 c2 61 90 01 06 88 10 90 00 } //00 00 
		$a_00_6 = {80 10 } //00 00 
	condition:
		any of ($a_*)
 
}