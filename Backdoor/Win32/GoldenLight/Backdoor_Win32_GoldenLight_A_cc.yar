
rule Backdoor_Win32_GoldenLight_A_cc{
	meta:
		description = "Backdoor:Win32/GoldenLight.A!cc,SIGNATURE_TYPE_PEHSTR_EXT,12 00 10 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {16 03 00 00 41 01 00 00 3d 03 00 90 01 20 00 00 16 00 04 00 05 00 0a 00 09 00 64 00 62 00 03 00 06 00 13 00 12 00 63 01 00 90 00 } //01 00 
		$a_01_1 = {16 03 00 01 04 10 00 01 00 00 15 b3 76 32 9f 46 4f 39 99 3b 84 ad 2d 5c bd da e2 2b 3e b3 19 04 7b 9a 70 09 52 a7 ae 42 d0 73 cf 78 1a 88 de eb 6e 25 9b 01 3d 3e 38 ad 41 4b 5c 7a 40 a7 d7 16 fa 7b 06 43 29 0a 88 63 23 33 9d 5f 8f dd 5e 9e ee 12 3e 07 ef 27 94 8d 8e 8f 6f 43 c2 45 ec ac 14 55 d7 8e d9 29 4f a0 16 24 cf 19 5c fd 86 42 0b ac 30 04 2f 2f 9a 45 76 2c d1 } //01 00 
		$a_01_2 = {27 99 71 c8 8b 8b 75 52 66 7a 47 94 57 02 4e 6b 56 63 94 ae fe 21 14 4a c2 06 3c f4 e9 a2 a9 0a df a5 61 72 24 f8 d1 2f 0d f0 40 46 e3 f8 f2 f0 a5 10 ca b5 5b 9e 23 9a c8 d4 79 b1 d2 93 bf 53 8b 75 ba bb 5f 86 60 fb 70 7b ff 21 2c 4e 30 40 07 4f 07 e3 e1 3c 6b 2d 7d 20 6a 5a 75 45 d9 2b c6 a6 f1 32 13 6d d7 aa b4 0b 49 0c c7 89 1e da cf 8c cc af 0a 4a 4e 9c 1c f3 07 99 d2 c0 e0 9f c7 fd 42 7a 48 ee be d6 95 5c 08 ee af 3d 14 03 00 00 01 01 16 03 00 00 38 aa 10 a9 b1 7d d1 a9 33 0b 29 7a 01 74 51 9b 82 8a 37 b8 f1 8a 1f 35 4e c8 27 1a a7 0b 68 bc 35 29 9e bb 02 d4 76 2d 4a d0 de 82 ed 42 5b d0 dc 9b cf e8 ba cf 27 7c a3 } //00 00 
		$a_00_3 = {5d 04 00 } //00 9e 
	condition:
		any of ($a_*)
 
}