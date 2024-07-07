
rule Backdoor_Win32_IRCbot_CL{
	meta:
		description = "Backdoor:Win32/IRCbot.CL,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4e 49 43 4b 20 25 73 25 63 } //1 NICK %s%c
		$a_01_1 = {42 75 5a 42 6f 54 } //1 BuZBoT
		$a_01_2 = {6a 47 6a 53 6a 4d 6a 56 6a 49 6a 52 6a 50 } //1 jGjSjMjVjIjRjP
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}