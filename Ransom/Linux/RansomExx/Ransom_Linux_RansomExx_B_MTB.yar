
rule Ransom_Linux_RansomExx_B_MTB{
	meta:
		description = "Ransom:Linux/RansomExx.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {48 89 c7 e8 a7 1b 00 00 89 45 cc 83 7d cc 00 0f 85 6f 01 00 00 48 8d 85 70 ee ff ff 48 83 c0 10 48 8d 15 10 0a 02 00 be 10 00 00 00 48 89 c7 e8 2d 14 01 00 89 45 cc 83 7d cc 00 0f 85 46 01 00 00 48 8d 85 70 ee ff ff 48 83 c0 28 48 8d 15 e5 0d 02 00 be 10 00 00 00 48 89 c7 e8 01 14 01 00 89 45 cc 83 7d cc 00 } //1
		$a_00_1 = {48 01 d0 48 be 58 58 58 58 58 58 58 58 58 bf 58 58 58 58 58 58 58 58 58 89 30 48 89 78 08 c7 40 10 58 58 58 58 c6 40 14 00 48 8d 95 60 ff ff ff 48 8b 45 f8 48 89 d6 48 89 c7 e8 18 ed 01 00 83 f8 ff 75 4c 48 8b 45 f8 48 8d 35 a0 ff 01 00 48 89 c7 e8 50 ed ff ff 48 89 45 f0 48 83 7d f0 00 74 31 48 8b 45 f0 48 89 c1 ba ec 01 00 00 be 01 00 00 00 48 8d 3d 7d ff 01 00 e8 d8 ed ff ff } //1
		$a_00_2 = {48 be 58 58 58 58 58 58 58 58 58 bf 58 58 58 58 58 58 58 58 58 89 30 48 89 78 08 c7 40 10 58 58 58 58 c6 40 14 00 48 8d 95 60 ff ff ff 48 8b 45 f8 48 89 d6 48 89 c7 e8 c8 eb 01 00 83 f8 ff 74 0f 48 8b 45 f8 48 89 c7 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}