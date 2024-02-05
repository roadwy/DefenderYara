
rule Backdoor_Win32_IRCbot_CL{
	meta:
		description = "Backdoor:Win32/IRCbot.CL,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 49 43 4b 20 25 73 25 63 } //01 00 
		$a_01_1 = {42 75 5a 42 6f 54 } //01 00 
		$a_01_2 = {6a 47 6a 53 6a 4d 6a 56 6a 49 6a 52 6a 50 } //00 00 
	condition:
		any of ($a_*)
 
}