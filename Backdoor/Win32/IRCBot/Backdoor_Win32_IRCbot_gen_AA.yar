
rule Backdoor_Win32_IRCbot_gen_AA{
	meta:
		description = "Backdoor:Win32/IRCbot.gen!AA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {25 73 20 22 22 20 22 6c 6f 6c 22 20 3a 25 73 0d 0a } //1
		$a_03_1 = {75 21 6a 3f 8d 45 c0 68 ?? ?? 40 00 50 e8 ?? ?? 00 00 ff 75 10 8d 45 c0 ff 75 10 50 68 ?? ?? 40 00 eb 5c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}