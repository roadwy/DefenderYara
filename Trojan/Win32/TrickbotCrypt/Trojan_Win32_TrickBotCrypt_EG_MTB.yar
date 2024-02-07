
rule Trojan_Win32_TrickBotCrypt_EG_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 02 8b 4d 90 01 01 8b 11 8b 4d 90 01 01 0f b6 14 11 03 15 90 01 04 8b 4d 90 01 01 0f b6 04 01 33 c2 8b 4d 90 01 01 8b 11 8b 4d 90 01 01 88 04 11 90 00 } //01 00 
		$a_81_1 = {4d 34 63 78 31 28 42 6d 58 3e 50 67 53 4b 38 3e 24 3f 39 25 6a 4b 40 52 55 25 30 59 59 25 49 5f 68 71 67 51 48 57 67 3c 24 40 6b 28 24 29 69 4d 36 33 40 58 77 2b 31 7a 78 72 4a 2b 6b 29 37 35 21 77 79 58 44 44 34 } //00 00  M4cx1(BmX>PgSK8>$?9%jK@RU%0YY%I_hqgQHWg<$@k($)iM63@Xw+1zxrJ+k)75!wyXDD4
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_TrickBotCrypt_EG_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 04 0a 8b 54 24 90 01 01 81 e2 90 01 04 03 c2 33 d2 f7 35 90 01 04 a1 90 01 04 8b d8 0f af d8 a1 90 01 04 2b d3 2b d7 8b 3d 90 01 04 2b d7 03 d0 8b 44 24 90 01 01 8a 14 0a 8a 18 32 da 8b 54 24 90 01 01 88 18 90 00 } //01 00 
		$a_03_1 = {0f b6 14 3b 03 c2 33 d2 f7 35 90 01 04 a1 90 01 04 89 6c 24 90 01 01 0f af c6 8d 2c 49 2b e8 a1 90 01 04 0f af e9 0f af e9 03 d5 8d 0c 76 8d 04 82 2b c1 8a 0c 38 8b 44 24 90 01 01 30 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}