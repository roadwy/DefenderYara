
rule Backdoor_Linux_Mirai_IG_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.IG!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {0a 00 0a 00 34 2e 30 30 32 30 32 31 0a 00 00 00 14 30 8d e5 04 60 8e e2 00 50 a0 e3 00 40 e0 e3 03 20 a0 e3 00 10 96 e5 00 00 a0 e3 0c 10 8d e5 c0 00 90 ef 08 00 8d e5 00 30 96 e5 04 30 2d e5 0d 30 a0 e1 00 20 a0 e1 08 00 d6 e5 04 00 2d e5 04 10 96 e5 0c 00 86 e2 02 a0 a0 e1 0f e0 a0 e1 18 f0 9d e5 04 d0 8d e2 04 30 9d e4 14 10 9d e5 04 10 8a e4 05 20 a0 e3 0c 10 9d e5 08 00 9d e5 7d 00 90 ef 00 00 9d e5 04 10 16 e5 01 50 80 e0 01 40 49 e0 00 e0 8f e2 0a f0 a0 e1 } //1
		$a_00_1 = {13 5f d6 09 30 8f 6d 1b 1c cb 06 a3 8b 34 3f b6 04 80 03 c3 bf 33 ba a7 09 e1 83 ef b3 93 bb 45 13 bc 02 b7 da 57 20 8a be e2 9b 23 b1 8b c3 92 e5 23 c6 1e 47 3b 92 e5 b7 0d a9 0e 23 40 f7 7b 00 47 c2 50 f3 81 b7 af ba 6f db 02 2c 1b f7 b4 fd 13 0a d7 12 cf ee f2 0f 1f 37 0e 7b f7 87 6c e2 97 0c 7d 37 9c d7 43 07 53 ba 8f 08 19 73 f7 8f 22 13 3e 1f ea e0 3b 3a e7 16 9e 82 24 1b 41 d8 a3 e1 d9 60 c3 f0 53 0c f2 93 87 80 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}