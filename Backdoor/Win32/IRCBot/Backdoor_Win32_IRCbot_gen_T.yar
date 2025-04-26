
rule Backdoor_Win32_IRCbot_gen_T{
	meta:
		description = "Backdoor:Win32/IRCbot.gen!T,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {7e 24 50 83 c0 0a 83 e0 fe 50 e8 ?? ?? ff ff 5a 66 c7 44 02 fe 00 00 83 c0 08 5a 89 50 fc c7 40 f8 01 00 00 00 } //1
		$a_01_1 = {8a 44 18 ff 8b cb 83 e1 7f 32 c1 8b 4d f8 8b 7d e0 0f b6 4c 39 ff 03 c9 c1 e9 02 32 c1 32 d0 88 55 ef 8b c3 83 e0 01 85 c0 75 1a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}