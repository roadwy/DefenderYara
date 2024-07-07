
rule Backdoor_Win32_IRCbot_gen_N{
	meta:
		description = "Backdoor:Win32/IRCbot.gen!N,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 ed 00 00 00 ff 36 68 09 12 d6 63 e8 f7 00 00 00 89 46 08 e8 a2 00 00 00 ff 76 04 68 6b d0 2b ca } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}