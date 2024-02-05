
rule Adware_AndroidOS_Zadmo_A_MTB{
	meta:
		description = "Adware:AndroidOS/Zadmo.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {20 54 a0 d9 51 df 47 ab 4a de 50 f7 3c ca 19 60 d9 56 93 09 a4 31 47 25 4b cc b1 54 8e 9a c2 2e c7 9d 3a 68 3b ae 1b 13 30 c2 47 2a 13 80 dd 13 f0 e4 7b c4 13 79 ec 3a 8d b1 7c e7 4b 71 d4 4e 5d a3 c2 5f ab 1e 49 ea e1 52 8f 6b 28 82 6b 09 93 08 5d 6a 25 60 c8 38 e8 87 94 a8 8f c6 d1 ec 27 3c 3d 2a f8 72 5d f7 cc 31 } //01 00 
		$a_00_1 = {44 40 08 9d eb 18 1b 19 79 4c 1b 19 f3 41 1c 18 01 b4 08 bc 53 40 63 40 14 9d 69 18 c9 18 75 4b c9 18 f9 41 09 19 c3 43 0b 43 63 40 0d 9d aa 18 d2 18 71 4b d2 18 1a 23 04 93 da 41 52 18 e3 43 13 43 4b 40 09 9d 28 18 c0 18 6c 4b c0 18 16 23 03 93 d8 41 83 18 c8 43 18 43 50 40 06 9d 2c 19 20 18 67 4c 00 19 11 24 09 94 e0 41 c4 18 d0 43 20 43 58 40 0c 9f 79 18 08 18 62 49 40 18 0b 26 f0 41 0d 96 07 19 d8 43 38 43 60 40 07 99 8a 18 10 18 5d 4a 80 18 04 99 c8 41 c2 19 e0 43 10 43 78 40 0f 99 cb 18 18 18 58 4b c0 18 03 9d e8 41 83 18 f8 43 18 43 50 40 0a 99 0c 19 20 18 54 4c 00 19 09 99 c8 41 c4 18 d0 43 20 43 58 40 12 99 cf 19 38 18 4f 4f c0 19 f0 41 07 19 d8 43 38 43 } //00 00 
	condition:
		any of ($a_*)
 
}