
rule Trojan_Win32_Zbot_GTR_MTB{
	meta:
		description = "Trojan:Win32/Zbot.GTR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 45 44 8b 00 8b 55 40 8a 14 0a 88 14 08 8b 45 10 8b 55 14 33 c6 8d 8c 01 90 01 04 8b 45 1c 8b 00 3b 48 54 72 d9 8b 45 1c 8b 08 0f b7 49 14 8b 10 8d 4c 0a 18 89 4d 24 8b 4d 08 8b 55 0c 33 ce 2b cf eb 62 90 00 } //0a 00 
		$a_02_1 = {8b 45 e8 8b 55 e4 69 c0 90 01 04 8b 5d 90 01 01 2b c2 33 d2 f7 f3 8b d1 69 c0 90 01 04 05 90 01 04 33 c6 2b d0 3b d7 0f 86 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}