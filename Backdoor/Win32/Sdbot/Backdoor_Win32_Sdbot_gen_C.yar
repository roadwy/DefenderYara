
rule Backdoor_Win32_Sdbot_gen_C{
	meta:
		description = "Backdoor:Win32/Sdbot.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,32 00 30 00 0b 00 00 "
		
	strings :
		$a_01_0 = {6b 69 6b 67 61 68 6a 63 65 77 66 } //10 kikgahjcewf
		$a_01_1 = {57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 6d 73 6b 69 6b 63 6f 6d 2e 65 78 65 } //10 WINDOWS\SYSTEM32\mskikcom.exe
		$a_01_2 = {4b 49 4b 42 6f 74 2e 65 78 65 } //10 KIKBot.exe
		$a_01_3 = {55 53 45 52 20 6b 69 6b 62 6f 74 20 6b 69 6b 62 6f 74 20 6b 69 6b 62 6f 74 20 3a 6b 69 6b 62 6f 74 } //10 USER kikbot kikbot kikbot :kikbot
		$a_01_4 = {6c 6f 6c 6f 6c 6b 69 6b } //1 lololkik
		$a_01_5 = {23 6b 69 6b } //5 #kik
		$a_01_6 = {4e 49 43 4b 20 25 73 } //1 NICK %s
		$a_01_7 = {4a 4f 49 4e 20 25 73 20 25 73 } //1 JOIN %s %s
		$a_01_8 = {50 52 49 56 4d 53 47 20 25 73 20 3a 25 73 } //1 PRIVMSG %s :%s
		$a_01_9 = {44 6f 77 6e 6c 6f 61 64 69 6e 67 20 25 73 20 74 6f 20 25 73 2e 2e 2e } //1 Downloading %s to %s...
		$a_01_10 = {4b 65 79 6c 6f 67 20 4f 4e 2e } //1 Keylog ON.
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*5+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=48
 
}