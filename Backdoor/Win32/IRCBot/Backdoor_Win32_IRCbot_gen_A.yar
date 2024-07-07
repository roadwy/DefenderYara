
rule Backdoor_Win32_IRCbot_gen_A{
	meta:
		description = "Backdoor:Win32/IRCbot.gen!A,SIGNATURE_TYPE_PEHSTR,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {72 6f 6f 74 } //1 root
		$a_01_1 = {21 40 23 24 } //1 !@#$
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {25 73 5c 63 24 5c 77 69 6e 6e 74 5c 73 79 73 74 65 6d } //1 %s\c$\winnt\system
		$a_01_4 = {25 73 5c 63 24 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d } //1 %s\c$\windows\system
		$a_01_5 = {25 73 5c 41 64 6d 69 6e 24 5c 73 79 73 74 65 6d } //1 %s\Admin$\system
		$a_01_6 = {25 73 5c 69 70 63 24 } //1 %s\ipc$
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}