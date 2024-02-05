
rule Trojan_Win32_Emotetcrypt_EP_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.EP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d d4 2b c1 03 05 90 01 04 03 05 90 01 04 03 05 90 01 04 03 05 90 01 04 8b 55 d8 03 d0 03 15 90 01 04 8b 45 dc 2b d0 03 15 90 01 04 03 15 90 01 04 03 15 90 01 04 8b 4d e0 03 d1 2b 15 90 01 04 8b 45 e4 2b d0 8b 4d 0c 8b 45 e8 88 04 11 e9 90 00 } //01 00 
		$a_81_1 = {76 7a 79 78 51 51 6a 74 6e 50 70 4d 31 6b 4d 74 50 32 5e 63 29 74 6f 41 4f 67 47 7a 4a 6e 41 28 78 34 6e 29 6d 5a 56 3f 5a 67 71 62 71 6c 73 3e 26 32 38 4b 62 33 30 33 68 55 6e 63 56 61 61 64 40 3f 4e 2a 41 25 57 32 65 42 68 44 4e 64 2b 6d 5f 42 6c 32 63 46 7a 6e 71 68 2a 76 72 44 70 48 50 47 6a 25 3f 5f 21 70 62 4c 70 } //00 00 
	condition:
		any of ($a_*)
 
}