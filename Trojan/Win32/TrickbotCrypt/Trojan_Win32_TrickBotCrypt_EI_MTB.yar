
rule Trojan_Win32_TrickBotCrypt_EI_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 14 38 8b 44 24 90 01 01 03 c3 89 44 24 90 01 01 0f b6 d2 8b c6 2b c1 0f b6 04 38 03 c2 33 d2 bb 90 01 04 f7 f3 8b 44 24 90 01 01 2b 15 90 01 04 03 54 24 30 03 d5 03 54 24 90 01 01 8a 14 3a 30 10 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_TrickBotCrypt_EI_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 08 03 55 f4 0f b6 02 89 45 e0 8b 4d 08 03 4d f4 0f b6 11 2b 55 f8 89 55 f8 79 90 01 01 68 90 01 04 68 90 01 04 e8 90 01 04 83 c4 08 8b 45 f8 05 00 01 00 00 89 45 f8 8b 4d 08 03 4d f4 8a 55 f8 88 11 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}