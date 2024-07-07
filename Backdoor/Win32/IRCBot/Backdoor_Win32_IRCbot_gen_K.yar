
rule Backdoor_Win32_IRCbot_gen_K{
	meta:
		description = "Backdoor:Win32/IRCbot.gen!K,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {eb 05 e8 f9 ff ff ff 5b 31 c9 66 b9 ff ff 80 73 0e ff 43 e2 f9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}