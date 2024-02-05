
rule Backdoor_Win32_IRCbot_GL{
	meta:
		description = "Backdoor:Win32/IRCbot.GL,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 72 63 2e 68 61 63 6b 74 2e 6f 72 67 } //01 00 
		$a_01_1 = {55 53 45 52 20 4e 61 79 72 41 20 30 20 2a 20 3a 4e 61 79 72 41 } //01 00 
		$a_01_2 = {5b 25 73 7c 25 73 25 63 5d 25 73 } //00 00 
	condition:
		any of ($a_*)
 
}