
rule Backdoor_Win32_IRCbot_KX{
	meta:
		description = "Backdoor:Win32/IRCbot.KX,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_02_0 = {42 6f 74 20 43 6f 6e 6e 65 63 74 65 64 20 74 6f 20 90 02 10 20 6f 6e 20 70 6f 72 74 20 36 36 36 90 00 } //01 00 
		$a_00_1 = {53 68 65 6c 6c 63 6f 64 65 20 75 73 65 64 3a 20 28 25 6c 64 } //01 00  Shellcode used: (%ld
		$a_00_2 = {21 52 65 76 65 72 73 65 53 68 65 6c 6c } //01 00  !ReverseShell
		$a_00_3 = {69 72 63 42 6f 74 2d 3e 6e 69 63 6b } //01 00  ircBot->nick
		$a_00_4 = {23 62 6f 74 2d 62 6f 74 2d 62 6f 74 } //01 00  #bot-bot-bot
		$a_00_5 = {4e 49 43 4b 20 42 6f 74 42 6f 74 42 6f 74 } //00 00  NICK BotBotBot
	condition:
		any of ($a_*)
 
}