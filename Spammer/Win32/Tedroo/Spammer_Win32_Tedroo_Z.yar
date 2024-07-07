
rule Spammer_Win32_Tedroo_Z{
	meta:
		description = "Spammer:Win32/Tedroo.Z,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 14 13 3e 00 6a 00 6a 00 ff 15 24 20 3e 00 89 45 bc c7 45 e0 00 00 00 00 83 45 e0 01 c7 45 e4 01 00 00 00 83 45 e4 01 c7 45 e8 03 00 00 00 c7 45 ec 04 00 00 00 c7 45 f0 05 00 00 00 c7 45 f4 01 00 00 00 83 45 f4 05 c7 45 f8 07 00 00 00 c7 45 fc 01 00 00 00 83 45 fc 07 6a 08 8d 45 e0 50 8d 45 cc 50 e8 84 fd ff ff 83 c4 0c a1 0b b6 3e 00 c1 e8 02 50 68 00 30 3e 00 8d 45 cc 50 e8 6a fd ff ff } //1
		$a_01_1 = {a1 52 28 56 a4 78 b0 0d 60 e8 0d 70 f4 fd 72 52 0d 67 fc 38 f9 c7 28 d9 2f 14 40 42 62 56 5f 13 be de c3 f0 9c 93 31 6d 2b 46 64 d3 b6 b7 02 0d 11 a0 7b d0 19 ff 72 1d 1a 7e 94 f5 c1 9b bc 8d } //2
		$a_01_2 = {f7 a5 6c 38 6b b9 b1 23 b6 15 78 b2 b1 0f 44 59 8d c7 a3 31 f5 49 58 40 e9 83 a5 3e 1e 8c d5 63 66 c4 3c df a8 c4 ff 7b b3 d6 84 f8 27 b4 5c af 1b af 65 c8 6b cf 0b 42 00 44 d6 c3 77 b6 4d 46 } //2
		$a_01_3 = {6f fb c8 1f 01 64 77 31 df 50 e9 a0 c4 82 9a 30 d1 03 97 38 d8 21 59 27 fc 28 3f dc 36 30 8f 2a c1 da 31 f2 2c b0 fd 96 f5 24 03 f4 99 2a 28 58 25 79 44 2d f1 6f ba ae 9c 2c 9b ea 28 de 8b 9a } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=2
 
}