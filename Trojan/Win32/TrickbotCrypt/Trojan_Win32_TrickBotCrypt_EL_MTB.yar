
rule Trojan_Win32_TrickBotCrypt_EL_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 04 0e 03 c2 33 d2 f7 35 90 01 04 8b 44 24 1c 83 c0 fe 0f af 05 90 01 04 2b d5 8b e9 03 ea 8a 14 28 8a 03 32 c2 8b 54 24 24 88 03 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_TrickBotCrypt_EL_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 95 5c ff ff ff 0f b6 82 00 10 00 00 89 45 90 01 01 8b 4d 90 01 01 03 8d 5c ff ff ff 0f b6 91 00 10 00 00 2b 55 90 01 01 89 55 90 01 01 79 90 09 03 00 8b 55 90 00 } //01 00 
		$a_03_1 = {05 00 01 00 00 89 45 90 01 01 8b 4d 90 01 01 03 8d 5c ff ff ff 8a 55 90 01 01 88 91 00 10 00 00 e9 90 09 03 00 8b 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}