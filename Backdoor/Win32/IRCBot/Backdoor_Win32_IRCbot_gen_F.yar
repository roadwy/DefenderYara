
rule Backdoor_Win32_IRCbot_gen_F{
	meta:
		description = "Backdoor:Win32/IRCbot.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {ff ff 60 6a 00 6a 00 6a 00 6a ff ff 15 90 01 03 00 85 c0 74 08 6a 00 ff 15 90 09 20 00 c6 85 90 01 02 ff ff c8 c6 85 90 01 02 ff ff 00 c6 85 90 01 02 ff ff 04 c6 85 90 01 02 ff ff 00 c6 85 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}