
rule Ransom_Linux_Trigona_D_MTB{
	meta:
		description = "Ransom:Linux/Trigona.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {75 31 e8 c6 b8 01 00 48 89 c3 48 89 de 48 ba d8 f6 66 00 00 00 00 00 bf 00 00 00 00 e8 74 bb 01 00 e8 cf 5f 01 00 48 89 df e8 6f ba 01 00 e8 c2 5f 01 00 48 8d 75 f0 } //1
		$a_00_1 = {eb 3d 66 44 89 e0 66 41 89 45 08 41 c7 45 18 00 00 00 00 41 8b 55 18 49 8b 45 10 48 01 d0 48 89 c3 0f b7 43 10 41 01 45 18 0f b7 43 10 41 01 45 04 48 8b 03 48 85 c0 74 87 48 89 d8 49 89 c6 4c 89 f0 } //1
		$a_00_2 = {46 69 6c 65 20 61 6c 72 65 61 64 79 20 65 6e 63 72 79 70 74 65 64 20 6f 72 20 72 65 6e 61 6d 65 64 } //1 File already encrypted or renamed
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}