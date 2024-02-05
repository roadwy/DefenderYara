
rule Backdoor_Win32_IRCbot_OP{
	meta:
		description = "Backdoor:Win32/IRCbot.OP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b d8 85 db 7e 29 bf 01 00 00 00 8b 45 fc 8a 44 38 ff 88 45 fb 8d 45 f4 8a 55 fb 4a e8 } //01 00 
		$a_01_1 = {4d 44 41 54 41 31 00 00 4d 44 41 54 41 32 } //00 00 
	condition:
		any of ($a_*)
 
}