
rule Backdoor_Linux_Yakuza_A_MTB{
	meta:
		description = "Backdoor:Linux/Yakuza.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {0d c0 a0 e1 00 d8 2d e9 04 b0 4c e2 60 d0 4d e2 68 00 0b e5 6c 10 0b e5 00 00 a0 e3 e2 07 00 eb 00 20 a0 e1 6c 30 1b e5 03 30 82 e0 14 30 0b e5 64 30 4b e2 7c 20 9f e5 03 e0 a0 e1 02 c0 a0 e1 0f 00 bc e8 0f 00 ae e8 0f 00 bc e8 0f 00 ae e8 0f 00 9c e8 07 00 ae e8 00 30 ce e5 68 20 1b e5 64 30 4b e2 03 00 a0 e1 02 10 a0 e1 7b 0d 00 eb 64 30 4b e2 03 00 a0 e1 3c 10 9f e5 71 08 00 eb 00 30 a0 e1 10 30 0b e5 02 00 00 ea } //1
		$a_00_1 = {94 21 ff 80 7c 08 02 a6 93 e1 00 7c 90 01 00 84 7c 3f 0b 78 90 7f 00 68 90 9f 00 6c 38 60 00 00 48 00 22 cd 7c 69 1b 78 80 1f 00 6c 7c 09 02 14 90 1f 00 0c 39 7f 00 10 3d 20 10 01 38 09 1b b4 7d 69 5b 78 39 60 00 2d 7d 23 4b 78 7c 04 03 78 7d 65 5b 78 48 00 3a f5 81 3f 00 68 38 1f 00 10 7c 03 03 78 7d 24 4b 78 48 00 3c 0d 38 1f 00 10 7c 03 03 78 3d 20 10 01 38 89 1b e4 48 00 25 a9 7c 60 1b 78 90 1f 00 08 48 00 00 10 } //1
		$a_03_2 = {63 64 20 2f 74 6d 70 3b 20 77 67 65 74 20 68 74 74 70 [0-20] 62 69 6e 73 2e 73 68 } //1
		$a_03_3 = {63 68 6d 6f 64 20 37 37 37 20 2a [0-04] 73 68 20 62 69 6e 73 2e 73 68 [0-04] 74 66 74 70 20 2d 67 [0-20] 2d 72 20 74 66 74 70 2e 73 68 } //1
		$a_03_4 = {73 68 20 74 66 74 70 2e 73 68 [0-04] 72 6d 20 2d 72 66 20 2a 2e 73 68 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}