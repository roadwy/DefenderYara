
rule TrojanSpy_AndroidOS_Chrysaor_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Chrysaor.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {30 a0 e3 c0 30 0b e5 00 01 1b e5 b8 34 9f e5 03 30 8f e0 03 10 a0 e1 b0 34 9f e5 03 30 94 e7 03 20 a0 e1 cc 90 01 03 00 30 a0 e1 c8 30 0b e5 00 01 1b e5 98 34 9f e5 03 30 8f e0 03 10 a0 e1 90 01 01 34 9f e5 03 30 94 e7 03 20 a0 e1 c2 90 01 03 00 30 a0 e1 c4 30 0b e5 00 01 1b e5 78 34 9f e5 03 30 8f e0 03 10 a0 e1 90 00 } //1
		$a_03_1 = {16 4c 16 4a 17 4d 7c 44 7a 44 03 20 21 1c 7d 44 ff 90 01 03 6b 68 01 2b 17 d0 12 4a 01 23 6b 60 7a 44 21 1c 03 20 ff 90 01 03 0f 48 10 49 10 4a 78 44 79 44 7a 44 2b 1c ff 90 01 03 0e 4a 03 20 21 1c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}