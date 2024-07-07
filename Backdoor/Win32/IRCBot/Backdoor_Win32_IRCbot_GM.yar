
rule Backdoor_Win32_IRCbot_GM{
	meta:
		description = "Backdoor:Win32/IRCbot.GM,SIGNATURE_TYPE_PEHSTR,17 00 17 00 06 00 00 "
		
	strings :
		$a_01_0 = {30 2e 30 2e 30 2e 30 20 77 77 77 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d } //10 0.0.0.0 www.microsoft.com
		$a_01_1 = {30 2e 30 2e 30 2e 30 20 77 77 77 2e 76 69 72 75 73 74 6f 74 61 6c 2e 63 6f 6d } //10 0.0.0.0 www.virustotal.com
		$a_01_2 = {64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //1 drivers\etc\hosts
		$a_01_3 = {62 6c 6f 63 6b 65 64 20 44 4e 53 3a 20 22 25 73 22 } //1 blocked DNS: "%s"
		$a_01_4 = {7b 25 73 7c 78 36 34 7c 25 73 7c 25 73 7d } //1 {%s|x64|%s|%s}
		$a_01_5 = {69 72 63 2e 68 65 63 6b 62 69 67 2e 63 6f 6d } //1 irc.heckbig.com
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=23
 
}