
rule Trojan_Linux_CobaltStrike_D_MTB{
	meta:
		description = "Trojan:Linux/CobaltStrike.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {51 0c 7c 62 2f dd d6 2a 37 8d 7e 68 54 c0 2f aa 8b dd 47 37 a8 b1 38 56 fc 62 b8 c8 dd 97 d7 7a 0b a7 57 2f a6 8b 0c dd 2a ff a1 98 4c b8 c8 c0 5a 59 dd 3e a7 7b 91 81 4f a5 32 a2 5c dd 17 0e 37 5c 64 e0 13 d0 24 17 66 dd cb c8 c0 27 2a bf c3 08 } //1
		$a_01_1 = {45 43 e8 89 8a d3 41 61 98 0d 40 bf 31 f8 70 87 81 c0 9d 28 45 fb 36 1c 14 9c 5e b6 01 1d f0 82 92 31 d2 85 bd 0f 09 69 6f 2b ca a5 61 3d be 92 52 83 80 b7 17 ca 40 b5 78 74 0f 76 90 50 d3 0e 28 a0 75 40 da 08 } //1
		$a_01_2 = {4e 44 08 7d 60 f9 a2 19 7d 04 96 f1 c0 2a 4f a0 22 2e 52 a7 63 b0 c5 21 a4 3e 01 61 34 7d 42 02 61 1c 33 5b e1 5c 02 1e 7e 59 15 13 b0 82 13 71 eb e0 03 39 3a 83 a0 81 60 a5 b8 5f 10 d8 44 cc } //1
		$a_01_3 = {31 4b 17 fd 9b c7 36 dc 79 4f 4c c2 25 57 bc 08 db 36 d8 e1 13 a1 70 ba d7 c0 99 10 61 f7 44 f4 13 fe 37 e4 34 3f 16 2e 4e 36 9d 38 81 97 d0 cd df 0f 07 85 9e 27 e4 e5 36 cc 8e 45 6d 92 b0 c8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}