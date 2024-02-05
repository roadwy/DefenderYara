
rule Trojan_Win32_Zbot_SIBA7_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SIBA7!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 08 03 4d 90 01 01 8b 55 90 01 01 89 0a 8b 45 90 01 01 8b 08 89 4d 90 01 01 8b 15 90 01 04 52 8b 45 90 1b 03 50 e8 90 01 04 83 c4 08 89 45 90 01 01 8b 4d 90 1b 02 8b 55 90 1b 07 89 11 90 18 8b 45 90 1b 00 83 c0 90 01 01 89 45 90 1b 00 8b 4d 90 1b 00 3b 4d 90 01 01 0f 83 90 01 04 90 02 1a 8b 55 90 1b 00 81 c2 90 01 04 89 15 90 1b 04 90 02 0a 8b 45 90 01 01 03 45 90 1b 00 89 45 90 1b 01 90 02 1a 8b 4d 90 1b 01 89 4d 90 1b 02 8b 15 90 1b 04 90 02 10 8b 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}