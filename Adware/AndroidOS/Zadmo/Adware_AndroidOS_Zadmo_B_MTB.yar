
rule Adware_AndroidOS_Zadmo_B_MTB{
	meta:
		description = "Adware:AndroidOS/Zadmo.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_00_0 = {01 70 20 8d f8 68 71 8d f8 69 41 69 24 8d f8 6a 71 8d f8 6b 31 8d f8 6c 21 8d f8 6d b1 4f f0 2d 0b 8d f8 6e 21 8d f8 6f 61 8d f8 70 51 63 25 8d f8 71 c1 8d f8 72 31 8d f8 73 01 8d f8 74 e1 4f f0 76 0e 8d f8 88 81 4f f0 64 08 8d f8 75 41 8d f8 76 e1 8d f8 77 b1 4f f0 68 0b 8d f8 48 51 36 25 8d f8 49 b1 8d f8 4a c1 8d f8 4b 91 8d f8 4c 81 8d f8 4d 71 8d f8 4e 51 34 25 8d f8 4f 51 8d f8 50 51 79 25 8d f8 51 71 8d f8 52 31 8d f8 53 } //1
		$a_00_1 = {44 5b 87 9a 36 d0 86 f8 4c b9 ea 80 fc 5e 5e 76 6a c1 40 ae e3 6a e4 70 0a f6 92 74 67 d8 73 91 b6 89 72 9c d5 e8 87 71 cc 49 09 7a ce d1 76 52 9a 73 a1 b3 15 5a 17 6b 58 7b da 54 ed 6e f4 e8 e3 3c 3b 8c 85 46 2a f8 0f f2 da c0 5a b9 } //1
		$a_00_2 = {ea d8 99 b9 0c f1 9f 38 93 97 85 d9 69 90 be 9f 8f 2f 61 4b 0d 98 91 ff 28 66 46 e0 a6 b2 95 fc 5b c3 1f d7 5c 51 02 88 5e e9 3a 34 23 90 7c 6d d9 2b a2 41 b2 1b ca 9a d2 e7 e0 b5 b9 6f f0 ee d4 4b 11 3f 2c e5 35 09 29 ef 8f bd 2a d2 8e 63 b0 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=1
 
}