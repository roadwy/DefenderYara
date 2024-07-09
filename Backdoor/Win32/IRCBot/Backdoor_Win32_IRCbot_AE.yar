
rule Backdoor_Win32_IRCbot_AE{
	meta:
		description = "Backdoor:Win32/IRCbot.AE,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b c1 99 f7 3d ?? ?? ?? 00 8a 82 ?? ?? ?? 00 8a 14 ?? 32 d0 } //1
		$a_01_1 = {64 a1 30 00 00 00 8b 40 0c 8b 40 14 } //1
		$a_03_2 = {6a 40 68 00 30 00 00 8b ?? 50 8b ?? 34 } //1
		$a_03_3 = {8b 48 34 51 ?? ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}