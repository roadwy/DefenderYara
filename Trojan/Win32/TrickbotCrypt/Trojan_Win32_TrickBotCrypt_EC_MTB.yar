
rule Trojan_Win32_TrickBotCrypt_EC_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f6 eb 8a 0c 31 2a c8 a0 90 01 04 f6 eb 8a 1d 90 01 04 02 c8 8a 45 00 2a cb 32 c1 42 88 45 00 90 09 0b 00 a0 90 01 04 f6 2d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_TrickBotCrypt_EC_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {0f b6 04 0e 89 54 24 10 0f b6 14 0f 03 c2 33 d2 f7 35 90 01 04 b8 02 00 00 00 2b 05 90 01 04 45 0f af c3 0f af c3 48 03 15 90 01 04 0f af c3 03 c2 0f b6 14 08 8b 44 24 10 30 10 90 00 } //05 00 
		$a_03_1 = {2b d0 2b 15 90 01 04 a1 90 01 04 0f af 05 90 01 04 0f af 05 90 01 04 03 d0 a1 90 01 04 0f af 05 90 01 04 0f af 05 90 01 04 03 45 08 8b 75 0c 8a 0c 0e 32 0c 10 8b 15 90 01 04 0f af 15 90 01 04 8b 45 ec 2b c2 2b 05 90 01 04 03 05 90 01 04 03 05 90 01 04 03 05 90 01 04 8b 55 0c 88 0c 02 e9 90 00 } //05 00 
		$a_81_2 = {3e 42 2a 58 21 55 66 5a 59 45 39 49 63 65 61 48 37 63 64 78 3c 68 5f 68 5e 31 44 44 33 51 74 75 73 79 3f 64 64 4f 38 7a 24 52 70 41 32 6f 25 38 28 66 66 3e 23 6b 65 55 4d 5f 46 73 33 55 7a 5e 64 62 65 43 24 71 2b 6e 58 70 6b 73 78 45 4d 57 67 75 77 55 7a 2b 6a 6e 76 } //00 00  >B*X!UfZYE9IceaH7cdx<h_h^1DD3Qtusy?ddO8z$RpA2o%8(ff>#keUM_Fs3Uz^dbeC$q+nXpksxEMWguwUz+jnv
	condition:
		any of ($a_*)
 
}