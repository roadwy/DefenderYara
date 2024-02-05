
rule Trojan_Win32_Emotetcrypt_GH_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 04 18 0f b6 0c 0a 03 c1 b9 90 01 04 99 f7 f9 8b 4d f4 2b 55 bc 03 55 b8 8a 04 32 8b 55 e8 30 04 0a 41 3b 4d 08 89 4d f4 b9 90 01 04 72 90 00 } //01 00 
		$a_81_1 = {59 77 61 57 29 43 65 2a 45 66 4f 53 6c 4e 74 49 63 33 5f 5f 77 4f 4a 59 5a 25 56 24 4d 7a 54 25 75 58 58 52 55 32 6f 36 5f 41 3c 41 71 75 46 35 44 74 3c 39 52 72 38 5f 30 6d 3f 39 43 51 50 4e 6c 26 77 31 76 68 44 7a 69 26 70 77 4d 56 4a 65 55 59 26 52 76 4d 73 31 36 36 43 6e 51 29 39 26 72 62 5e 39 49 25 } //00 00 
	condition:
		any of ($a_*)
 
}