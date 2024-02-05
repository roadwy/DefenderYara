
rule Trojan_Win32_EmotetCrypt_DH_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b c3 83 c0 02 0f af c1 8d 4e 01 03 d0 0f af 0d 90 01 04 8b 44 24 1c 2b d1 8b 0d 90 01 04 8a 18 2b d1 03 d6 8b 4c 24 24 8a 14 3a 32 da 88 18 90 00 } //01 00 
		$a_81_1 = {3f 44 21 75 3f 58 29 6b 72 54 7a 64 77 24 61 6e 4d 34 70 5f 24 62 7a 51 3f 6a 37 3f 72 45 6e 39 38 41 6e 3f 33 2b 30 56 3e 5a 40 72 78 31 25 70 70 6d 28 56 4d 43 73 24 36 6b 54 58 6b 4d 34 6e 39 55 61 47 4f 5e 33 67 4c 4f 46 49 67 6a 3c 69 73 74 51 49 43 58 34 2b 56 63 56 79 74 2b 59 55 55 40 51 33 6a 47 4b 34 4c 70 39 24 67 57 76 31 } //00 00 
	condition:
		any of ($a_*)
 
}