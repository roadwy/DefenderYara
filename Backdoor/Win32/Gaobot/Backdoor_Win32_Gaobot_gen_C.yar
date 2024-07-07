
rule Backdoor_Win32_Gaobot_gen_C{
	meta:
		description = "Backdoor:Win32/Gaobot.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 08 00 0a 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 6b 65 79 6c 6f 67 2e 74 78 74 } //1 c:\windows\keylog.txt
		$a_01_1 = {66 75 63 6b 69 6e 67 20 65 72 72 6f 72 } //1 fucking error
		$a_01_2 = {46 6f 75 6e 64 20 54 69 62 65 72 69 61 6e 20 53 75 6e 20 43 44 4b 65 79 20 28 25 73 29 2e } //1 Found Tiberian Sun CDKey (%s).
		$a_01_3 = {4a 4f 49 4e 20 25 73 20 25 73 } //1 JOIN %s %s
		$a_01_4 = {50 52 49 56 4d 53 47 20 25 73 20 3a } //1 PRIVMSG %s :
		$a_01_5 = {69 6e 76 61 6c 69 64 20 6e 69 63 6b 21 } //1 invalid nick!
		$a_01_6 = {4b 65 79 6c 6f 67 67 65 72 20 6c 6f 67 67 69 6e 67 20 74 6f 20 25 73 } //1 Keylogger logging to %s
		$a_01_7 = {5b 6e 74 2d 73 63 61 6e 5d 20 6e 6f 74 20 63 75 72 72 65 6e 74 6c 79 20 73 63 61 6e 6e 69 6e 67 } //1 [nt-scan] not currently scanning
		$a_01_8 = {75 73 65 72 70 61 73 73 77 6f 72 64 } //1 userpassword
		$a_01_9 = {55 47 4c 59 20 42 4f 54 20 31 2e 30 20 62 79 20 65 72 69 63 20 61 6e 64 20 76 69 63 65 } //1 UGLY BOT 1.0 by eric and vice
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=8
 
}