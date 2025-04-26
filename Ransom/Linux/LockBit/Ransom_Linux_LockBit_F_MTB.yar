
rule Ransom_Linux_LockBit_F_MTB{
	meta:
		description = "Ransom:Linux/LockBit.F!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f 84 1d 00 00 00 bb 60 d5 43 00 0f 1f 44 00 00 48 83 eb 08 ff d0 48 8b 03 48 83 f8 ff 0f 85 ed ff ff ff 48 83 c4 08 } //1
		$a_01_1 = {0f 84 2a 00 00 00 e8 a6 1b 00 00 48 89 c2 b8 60 b4 43 00 48 8b 4c 24 18 48 8d 9c 24 10 11 00 00 48 89 de 48 89 c7 b8 00 00 00 00 e8 87 1b 00 00 48 8b 44 24 18 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}