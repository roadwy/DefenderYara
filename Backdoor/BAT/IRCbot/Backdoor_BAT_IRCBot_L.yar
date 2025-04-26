
rule Backdoor_BAT_IRCBot_L{
	meta:
		description = "Backdoor:BAT/IRCBot.L,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 6f 6f 70 42 6f 74 } //2 MoopBot
		$a_01_1 = {42 6f 74 43 68 61 6e 6e 65 6c } //1 BotChannel
		$a_01_2 = {21 00 64 00 6c 00 65 00 78 00 65 00 63 00 20 00 } //1 !dlexec 
		$a_03_3 = {21 00 62 00 61 00 6e 00 20 00 ?? ?? 21 00 64 00 6c 00 20 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}