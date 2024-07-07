
rule Backdoor_Win32_IRCbot_gen_J{
	meta:
		description = "Backdoor:Win32/IRCbot.gen!J,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 64 03 40 30 78 0c 8b 40 0c 8b 70 1c ad 8b 40 08 eb 09 8b 40 90 09 0a 00 00 43 3a 5c 55 2e 65 78 65 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}