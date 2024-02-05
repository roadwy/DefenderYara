
rule Trojan_Win32_TrickBotCrypt_EE_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 08 03 45 f8 0f b6 08 89 4d f4 8b 55 08 03 55 f8 0f b6 02 2b 45 fc 89 45 fc 79 90 01 01 8b 4d fc 81 c1 00 01 00 00 89 4d fc 8b 55 08 03 55 f8 8a 45 fc 88 02 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_TrickBotCrypt_EE_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 0a 03 c1 33 d2 f7 35 90 01 04 89 55 f8 8b 15 90 01 04 0f af 15 90 01 04 8b 45 ec 2b c2 90 00 } //01 00 
		$a_03_1 = {2b c2 2b 05 90 01 04 8b 55 0c 8b 75 08 8a 0c 0a 32 0c 06 90 00 } //01 00 
		$a_03_2 = {03 c6 03 d0 03 15 90 01 04 8b 45 0c 88 0c 10 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}