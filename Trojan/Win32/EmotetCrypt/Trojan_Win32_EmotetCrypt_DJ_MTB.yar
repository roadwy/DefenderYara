
rule Trojan_Win32_EmotetCrypt_DJ_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 2a 03 c2 33 d2 89 6c 24 18 bd 90 01 04 f7 f5 8b 44 24 44 8b 6c 24 20 83 c5 01 89 6c 24 20 2b 54 24 14 2b 54 24 1c 2b d7 2b d1 03 d6 0f b6 14 02 8b 44 24 3c 30 54 28 ff 81 fd 90 01 04 0f 82 90 00 } //1
		$a_81_1 = {6c 45 5a 34 7a 78 38 39 5e 6e 5e 6f 72 46 49 62 57 4b 4f 76 62 4e 31 4b 70 34 4d 26 25 47 2b 37 37 4f 49 5e 42 6e 61 38 35 70 38 79 79 70 4e 5f 34 4f 65 23 6c 4a 62 4c 2a 55 6f 71 40 59 5a 5f 46 54 26 51 5e 5f 38 37 53 54 49 37 3f 68 43 36 30 41 30 26 64 2a 62 4d 50 40 3f 4e 35 } //1 lEZ4zx89^n^orFIbWKOvbN1Kp4M&%G+77OI^Bna85p8yypN_4Oe#lJbL*Uoq@YZ_FT&Q^_87STI7?hC60A0&d*bMP@?N5
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}