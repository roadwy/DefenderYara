
rule Adware_AndroidOS_Zadmo_C_MTB{
	meta:
		description = "Adware:AndroidOS/Zadmo.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {00 04 00 4d 45 54 41 2d 49 4e 46 2f 4d 41 4e 49 46 45 53 54 2e 4d 46 fe ca 00 00 65 8d 31 0b c2 30 10 85 f7 40 fe c3 8d 8a 24 b4 0e 56 b3 d5 ba 08 8a 83 e2 2a 67 73 c5 42 9a 94 24 43 fd f7 a6 45 50 28 b7 bd f7 be ef ce 68 db 86 42 14 77 f2 a1 75 56 41 2e 33 ce 8e 5d 6f a8 23 1b 31 a6 30 95 56 3b af c0 05 e2 ac b4 7f eb b2 c7 fa 45 90 b2 04 ee e4 66 86 de da 68 e8 4b ce ac bf 97 e3 71 76 a0 41 9c 5c 3d d5 0a 6a 83 21 50 90 9a 06 ce ae 84 86 b4 82 06 cd a8 aa 3c 61 24 2d f6 ef } //1
		$a_00_1 = {41 0e d0 15 48 0e c0 15 02 46 0e cc 15 48 0e d0 15 48 0e c0 15 4d 0e c8 15 41 0e cc 15 41 0e d0 15 48 0e c0 15 43 0e c8 15 41 0e cc 15 44 0e d0 15 48 0e c0 15 47 0e c4 15 4e 0e c8 15 41 0e cc 15 42 0e d0 15 48 0e c0 15 5f 0e c4 15 41 0e c8 15 41 0e cc 15 42 0e d0 15 48 0e c0 15 43 0e c4 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}