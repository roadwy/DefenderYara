
rule Backdoor_Win32_IRCbot_gen_H{
	meta:
		description = "Backdoor:Win32/IRCbot.gen!H,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b9 a0 05 00 00 40 40 f7 f1 66 83 65 ?? 00 33 c0 b9 ff 01 00 00 f3 ab 66 ab 69 d2 60 ea 00 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}