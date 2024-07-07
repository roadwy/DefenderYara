
rule Ransom_Win64_Ryuk_PC_MTB{
	meta:
		description = "Ransom:Win64/Ryuk.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 74 8b 4c 24 10 8b f5 c1 ee 05 03 74 24 7c 03 f8 03 cd 33 f9 81 3d 90 01 04 72 07 00 00 89 1d 90 01 04 89 1d 90 01 04 75 90 00 } //10
		$a_02_1 = {06 ee a0 db c7 05 90 01 04 ff ff ff ff 33 f7 29 74 24 60 89 5c 24 14 81 f3 07 eb dd 13 81 6c 24 14 52 ef 6f 62 b8 41 e5 64 03 81 6c 24 14 68 19 2a 14 81 44 24 14 be 08 9a 76 8b 5c 24 60 8b 4c 24 14 8b fb d3 e7 03 7c 24 6c 81 3d 90 01 04 1a 0c 00 00 75 90 00 } //10
		$a_02_2 = {8b fd c1 e7 04 81 3d 90 01 04 a2 07 00 00 c7 05 90 01 04 b4 1a 3a df 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_02_2  & 1)*1) >=21
 
}