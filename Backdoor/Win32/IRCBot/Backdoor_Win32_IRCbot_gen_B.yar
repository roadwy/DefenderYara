
rule Backdoor_Win32_IRCbot_gen_B{
	meta:
		description = "Backdoor:Win32/IRCbot.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1c 00 0a 00 00 "
		
	strings :
		$a_01_0 = {64 69 72 78 39 2e 65 78 65 } //5 dirx9.exe
		$a_01_1 = {57 69 6e 6a 61 76 61 20 78 6d 6c } //5 Winjava xml
		$a_00_2 = {4a 4f 49 4e } //5 JOIN
		$a_00_3 = {4e 49 43 4b } //5 NICK
		$a_00_4 = {50 52 49 56 4d 53 47 } //5 PRIVMSG
		$a_01_5 = {74 68 72 65 61 64 73 } //1 threads
		$a_01_6 = {6b 69 6c 6c 74 68 72 65 61 64 } //1 killthread
		$a_01_7 = {65 78 65 63 75 74 65 } //1 execute
		$a_01_8 = {6c 69 73 74 70 72 6f 63 65 73 73 65 73 } //1 listprocesses
		$a_01_9 = {6b 69 6c 6c 70 72 6f 63 65 73 73 } //1 killprocess
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_00_2  & 1)*5+(#a_00_3  & 1)*5+(#a_00_4  & 1)*5+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=28
 
}