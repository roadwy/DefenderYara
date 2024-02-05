
rule Trojan_Win32_Zbot_SIBA6_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SIBA6!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b 02 03 05 90 01 04 8b 4d 90 01 01 03 0d 90 1b 00 89 01 8b 15 90 1b 00 81 c2 90 01 04 8b 45 90 1b 01 03 05 90 1b 00 33 10 8b 4d 90 1b 01 03 0d 90 1b 00 89 11 90 18 a1 90 1b 00 83 c0 04 a3 90 1b 00 8b 0d 90 1b 00 3b 4d 90 01 01 73 90 01 01 8b 55 90 1b 01 03 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}