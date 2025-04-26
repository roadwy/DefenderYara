
rule Backdoor_Win32_IRCbot_FE{
	meta:
		description = "Backdoor:Win32/IRCbot.FE,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {5a 79 6d 61 20 47 72 6f 75 70 } //1 Zyma Group
		$a_01_1 = {5b 61 75 74 6f 72 75 6e 5d 0d 0a 73 68 65 6c 6c 65 78 65 63 75 74 65 3d 25 73 } //1 慛瑵牯湵൝猊敨汬硥捥瑵㵥猥
		$a_01_2 = {50 52 49 56 4d 53 47 20 25 73 20 3a 25 73 25 73 25 73 25 73 25 73 25 69 } //1 PRIVMSG %s :%s%s%s%s%s%i
		$a_01_3 = {3a 21 75 64 70 66 6c 6f 6f 64 } //1 :!udpflood
		$a_01_4 = {3a 21 72 65 63 6f 6e } //1 :!recon
		$a_01_5 = {3a 21 75 70 64 61 74 65 } //1 :!update
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}