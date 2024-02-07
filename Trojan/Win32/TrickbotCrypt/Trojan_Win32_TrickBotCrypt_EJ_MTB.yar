
rule Trojan_Win32_TrickBotCrypt_EJ_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 04 0e 03 c2 33 d2 f7 35 90 01 04 8b 44 24 18 8b 5c 24 1c 2b d0 a1 90 01 04 2b d3 8b 5c 24 20 2b d0 a1 90 01 04 03 d3 03 d0 8b 44 24 10 8a 1c 28 8a 14 0a 32 da 88 1c 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_TrickBotCrypt_EJ_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 55 e4 8b 12 8b 75 08 33 db 8a 1c 16 03 1d 90 01 04 8a 04 08 32 c3 8b 0d 90 01 04 0f af 0d 90 01 04 8b 15 90 00 } //01 00 
		$a_81_1 = {47 55 55 72 6c 35 37 33 21 39 79 25 6a 70 30 34 29 4b 2b 33 73 67 53 6d 74 40 5a 38 3f 5f 56 58 2b 35 25 33 37 31 65 2b 41 78 75 70 76 3c 21 6a 3c 24 5e 58 44 68 25 61 4a 4e 4a 71 3f 2a 3f 6d 30 24 53 } //00 00  GUUrl573!9y%jp04)K+3sgSmt@Z8?_VX+5%371e+Axupv<!j<$^XDh%aJNJq?*?m0$S
	condition:
		any of ($a_*)
 
}