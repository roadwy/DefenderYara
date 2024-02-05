
rule Trojan_Win32_Zbot_AS_MTB{
	meta:
		description = "Trojan:Win32/Zbot.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {2b d8 bf eb 00 00 00 31 3a 8d 1c 10 02 db 8b d9 8b cb 8b 32 1b d8 21 fb 81 c6 04 00 00 00 89 32 76 } //00 00 
	condition:
		any of ($a_*)
 
}