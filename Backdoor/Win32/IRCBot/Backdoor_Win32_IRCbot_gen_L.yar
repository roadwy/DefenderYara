
rule Backdoor_Win32_IRCbot_gen_L{
	meta:
		description = "Backdoor:Win32/IRCbot.gen!L,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 03 57 8d 5e 1c 6a 01 68 00 00 00 80 53 ff 56 04 89 45 fc 8d 86 20 01 00 00 50 57 57 ff 56 08 89 45 08 ff 56 0c 3d b7 00 00 00 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}