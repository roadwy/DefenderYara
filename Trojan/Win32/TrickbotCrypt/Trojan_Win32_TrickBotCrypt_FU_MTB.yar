
rule Trojan_Win32_TrickBotCrypt_FU_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.FU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b 45 0c 89 4d f8 8b 0d 90 01 04 2b d9 6b c9 05 03 1d 90 01 04 03 5d fc 03 d8 8b 45 f4 0f b6 04 30 03 c2 33 d2 f7 35 90 01 04 2b d1 03 d7 03 15 90 01 04 8a 04 32 30 03 90 00 } //05 00 
		$a_81_1 = {3c 52 33 61 5f 63 5e 6d 43 4e 77 34 2b 5e 36 4d 6c 65 37 3c 47 48 5a 49 58 39 6a 69 6d 3e 45 4a 57 39 3c 46 4c 40 31 55 40 75 37 54 6b 41 57 3e 24 36 75 4a 62 6d 6b 34 23 58 76 41 50 6d 24 38 } //00 00 
	condition:
		any of ($a_*)
 
}