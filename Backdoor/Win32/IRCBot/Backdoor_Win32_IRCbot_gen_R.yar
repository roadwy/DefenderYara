
rule Backdoor_Win32_IRCbot_gen_R{
	meta:
		description = "Backdoor:Win32/IRCbot.gen!R,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 09 00 00 "
		
	strings :
		$a_01_0 = {50 52 49 56 4d 53 47 20 25 73 20 3a 25 6c 75 25 6c 75 25 6c 75 25 6c 75 } //1 PRIVMSG %s :%lu%lu%lu%lu
		$a_01_1 = {25 73 20 3a 43 66 74 70 20 73 65 74 20 74 6f 3a 20 25 73 3a 25 64 } //1 %s :Cftp set to: %s:%d
		$a_01_2 = {50 52 49 56 4d 53 47 20 25 73 20 3a 4d 53 4e 20 6c 6f 6c 20 73 74 61 72 74 65 64 } //1 PRIVMSG %s :MSN lol started
		$a_01_3 = {50 52 49 56 4d 53 47 20 25 73 20 3a 4b 65 79 62 6f 61 72 64 20 63 61 70 74 75 72 65 } //1 PRIVMSG %s :Keyboard capture
		$a_01_4 = {56 4e 43 25 64 2e 25 64 20 25 73 3a 20 25 73 20 2d 20 5b 41 75 74 68 42 79 70 61 73 73 5d } //1 VNC%d.%d %s: %s - [AuthBypass]
		$a_01_5 = {26 65 63 68 6f 20 67 65 74 20 25 73 20 3e 3e 20 } //1 &echo get %s >> 
		$a_01_6 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 3d } //1 shell\open\command=
		$a_01_7 = {5b 70 53 74 6f 72 65 5d 00 } //1
		$a_01_8 = {3a 46 74 70 73 65 72 76 65 72 20 73 65 74 20 74 6f 3a 20 25 73 } //1 :Ftpserver set to: %s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=5
 
}