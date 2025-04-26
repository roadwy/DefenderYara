
rule Trojan_Linux_SSHDoor_F_MTB{
	meta:
		description = "Trojan:Linux/SSHDoor.F!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {56 d3 03 b6 95 78 9e 7c 1c c4 2c 19 86 7e 6a 9e be f8 df 0f 3f 7e 96 7c c3 3b 79 1c a1 9f a9 0f 43 66 4b 10 9e fb 6e 0f a2 5a ef 90 f9 2c 58 be 41 4d 9d 7c 25 a7 1b e0 a7 9b 93 1c d1 5f 39 0f be 86 ef 0e b9 2b 6b 15 3a 0d 85 b3 50 b5 a8 10 cf 4a ae ff 08 2c ae ff cb 44 77 12 4e 69 da b0 11 89 99 7c 71 93 c5 ba 52 8c 28 21 01 23 f9 a4 ea 3d 9d 7c f9 6b 2e 8c 60 98 ef 12 49 eb db 08 cf da 93 1c 38 40 0c af 6a 65 5d 14 19 dc 77 89 0b 0f b5 a5 7d 1b 76 } //1
		$a_01_1 = {66 49 49 22 c5 9f 2c fc 25 56 36 64 12 16 01 a9 ef 21 63 0f 8e 68 b0 6e bc 8b a8 af 81 74 82 0d 46 a4 81 10 6a f6 a3 b6 40 8f 1d fd 7b c7 54 d2 86 23 b6 b1 57 db 93 1c b5 e9 5a f1 36 15 15 65 72 47 9c 7c 84 9b 87 ff 95 b1 5d e0 b3 15 9a 7c 9a 91 08 ff e4 9e e0 ff 97 2b 26 fe c0 e5 95 7c d3 33 b2 a3 28 aa 3f 7e d6 0e 3f 0f 05 50 85 1b 26 76 fa 3b ef 0b 51 f9 be 27 15 36 d8 ec 70 ac 67 55 61 10 } //1
		$a_01_2 = {11 0f 7d 60 9c 7c 0c df 03 ab ae 60 87 ff e6 65 84 ba ac 3a 80 0f e9 44 6d 77 cf 38 39 0f 30 20 fe 0f 4e 88 e0 09 19 d1 78 85 6a 4e c2 ba e3 ad c6 1b ef b7 06 1e 20 cf 09 fd 94 19 68 f6 c5 b9 9c 40 5c c0 09 3e 55 cc 0a 83 56 33 66 0f 47 01 75 0f 26 21 67 69 b1 b0 a8 94 8f f5 c8 87 e4 de 93 1c 2a 9e 07 fd 51 ee 11 e3 ad 70 0e af fe ec 84 14 d2 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}