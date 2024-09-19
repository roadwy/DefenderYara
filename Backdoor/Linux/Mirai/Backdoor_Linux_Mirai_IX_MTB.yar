
rule Backdoor_Linux_Mirai_IX_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.IX!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 05 ca 7f 16 9c 11 f9 89 00 00 00 00 02 9d 74 8b 45 aa 7b ef b9 9e fe ad 08 19 ba cf 41 e0 16 a2 32 6c f3 cf f4 8e 3c 44 83 c8 8d 51 45 6f 90 95 23 3e 00 97 2b 1c 71 b2 4e c0 61 f1 d7 6f c5 7e f6 48 52 bf 82 6a a2 3b 65 aa 18 7a 17 38 c3 81 27 c3 47 fc a7 35 ba fc 0f 9d 9d 72 24 9d fc 02 17 6d 6b b1 2d 72 c6 e3 17 1c 95 d9 69 99 57 ce dd df 05 dc 03 94 56 04 3a 14 e5 ad 9a 2b 14 30 3a 23 a3 25 ad e8 e6 39 8a 85 2a c6 df e5 5d 2d a0 2f 5d 9c d7 2b 24 fb b0 9c c2 ba 89 b4 1b 17 a2 } //1
		$a_01_1 = {00 6b 22 03 38 5a 35 5a 7d 5e 24 18 29 05 29 14 30 46 6d 01 2d 5a 2d 09 3e 4b 35 09 32 44 6e 18 35 5e 2c 0c 76 52 2c 0c 71 4b 31 10 31 43 22 01 29 43 2e 0e 72 52 2c 0c 66 5b 7c 50 73 13 6d 09 30 4b 26 05 72 4b 37 09 3b 06 28 0d 3c 4d 24 4f 2a 4f 23 10 71 43 2c 01 3a 4f 6e 01 2d 44 26 4c 77 05 6b 5b 2c 17 71 4e 65 06 20 10 2d 46 28 03 3c 5e 28 0f 33 05 32 09 3a 44 24 04 70 4f 39 03 35 4b 2f 07 38 11 37 5d 3f 19 7a 11 60 1a 6f 57 00 6b 22 03 38 5a 35 4d 18 44 22 0f 39 43 2f 07 67 0a 26 1a 34 5a 6d 40 39 4f 27 0c 3c 5e } //1
		$a_01_2 = {65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 } //2 example.ulfheim.net
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=3
 
}