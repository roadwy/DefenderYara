
rule Trojan_Win32_ShipUp_BK_MTB{
	meta:
		description = "Trojan:Win32/ShipUp.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {8c 79 15 cc 8d cb 44 b0 ee 62 a1 29 5e 68 22 63 c4 23 8d 27 18 ab 32 2a 1f a1 3e 98 7b 73 a8 07 21 48 ee a9 d8 0e 49 97 00 66 cb 93 6e 05 24 e7 a6 7e 00 d4 9c 5e f5 98 57 0f e1 2b f7 bf 20 33 da 99 1d 67 07 fc c4 a0 37 dd b0 12 5c f0 b8 00 82 19 ca 89 ff 49 da a2 0e 77 0e c0 7f 67 58 ba f0 48 df 85 } //1
		$a_01_1 = {b9 79 37 9e e9 4e 69 35 da 02 f1 e1 2a 8f a7 66 27 5c d4 0a 32 81 69 02 58 43 da 04 d0 01 14 7a 06 0c a0 b2 37 1c 2d 11 ac 8b 95 60 b0 13 f9 8e 7a 7e 46 09 86 d9 50 f5 03 02 07 e5 14 76 d3 a8 2c 4b 46 dc 56 c6 0d 88 24 d8 e0 c6 c8 ed 02 60 b0 52 25 52 26 03 0c ff c3 02 b1 8a 38 } //1
		$a_01_2 = {94 f8 43 f7 4a bd 09 92 b2 11 84 09 c7 f3 85 21 e7 3e a7 c6 b1 d8 eb 6a cd 2a 2a fa 17 d6 b8 ea a0 21 fa bf 4b 01 ca 9b 6a ee 8b 25 c6 f6 95 3a 09 f8 fd 97 d8 ff 97 cc c9 2d cf 40 e6 c8 98 33 97 16 9f d2 b3 ea 29 af 2a bd 2b 96 ff 64 fd bc 39 2d 12 54 24 c1 e8 } //1
		$a_01_3 = {d7 b4 09 92 e2 93 a6 80 15 38 53 4d c7 ea b6 00 63 b5 2f 76 39 66 ef 2b 1f 06 78 6a 80 9a fb 97 7a f6 14 38 a1 ca 00 3e 7b 1f 9b 87 f5 3f 00 9f 5f df 02 05 3b 98 16 17 04 d0 36 00 65 0b a0 8c 14 4d 00 ea fc bc c4 79 f2 46 a2 00 cf 11 8e 37 42 93 4c 2f 01 84 ae a1 f8 fd f3 f7 ec 54 db } //1
		$a_01_4 = {2e 62 6f 6f 74 } //2 .boot
		$a_01_5 = {2e 74 68 65 6d 69 64 61 } //2 .themida
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=6
 
}