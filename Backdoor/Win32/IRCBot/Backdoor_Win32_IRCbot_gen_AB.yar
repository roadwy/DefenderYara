
rule Backdoor_Win32_IRCbot_gen_AB{
	meta:
		description = "Backdoor:Win32/IRCbot.gen!AB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 73 20 25 73 20 22 22 20 22 6c 6f 6c 22 20 3a 25 73 } //1 %s %s "" "lol" :%s
		$a_03_1 = {85 c0 59 76 15 8a 83 ?? ?? 40 00 55 30 04 3e 43 e8 ?? ?? 00 00 3b d8 59 72 eb } //1
		$a_03_2 = {59 39 45 f8 73 1b 8b 45 08 03 45 fc 8b 4d f8 8a 00 32 81 ?? ?? 40 00 8b 4d 08 03 4d fc 88 01 eb ce } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}