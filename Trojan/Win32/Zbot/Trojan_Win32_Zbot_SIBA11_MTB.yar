
rule Trojan_Win32_Zbot_SIBA11_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SIBA11!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {3b 4d 0c 0f 83 90 01 04 90 02 10 8b 55 90 01 01 81 c2 90 01 04 89 15 90 01 04 8b 45 08 03 45 90 1b 02 8b 08 03 4d 90 1b 02 8b 55 08 03 55 90 1b 02 89 0a 90 02 10 8b 0d 90 1b 04 89 4d 90 01 01 8b 55 90 1b 0a 89 55 90 01 01 8b 45 90 1b 0c 89 45 90 01 01 83 7d 90 1b 02 90 01 01 90 18 8b 4d 08 03 4d 90 1b 02 8b 11 33 55 90 1b 0e 8b 45 08 03 45 90 1b 02 89 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}