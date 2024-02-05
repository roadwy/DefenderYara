
rule Backdoor_Win32_IRCbot_CK{
	meta:
		description = "Backdoor:Win32/IRCbot.CK,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 70 70 44 61 74 61 25 5c 73 63 68 6f 73 74 2e 65 78 65 } //01 00 
		$a_01_1 = {63 6d 64 20 2f 63 20 52 45 47 20 41 44 44 20 48 4b 43 55 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 56 20 53 43 56 48 4f 53 54 } //01 00 
		$a_01_2 = {6e 64 65 74 65 63 74 2e 73 79 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}