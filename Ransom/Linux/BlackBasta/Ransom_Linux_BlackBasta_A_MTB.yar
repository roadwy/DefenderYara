
rule Ransom_Linux_BlackBasta_A_MTB{
	meta:
		description = "Ransom:Linux/BlackBasta.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {4a 03 04 c2 4e 8b 0c c6 49 89 c2 0f 92 c0 45 31 db 4d 39 d1 0f b6 c0 41 0f 92 c3 4d 29 d1 4e 89 0c c7 49 83 c0 01 4c 01 d8 49 39 c8 } //1
		$a_00_1 = {4c 89 f2 48 33 14 f7 4c 89 d1 4c 01 e2 41 0f 92 c4 49 33 0c f3 45 0f b6 e4 4c 01 e9 41 0f 92 c5 48 31 ca 4c 31 c2 45 0f b6 ed 48 01 da 0f 92 c3 48 89 14 f0 48 83 c6 01 48 39 f5 0f b6 db } //1
		$a_00_2 = {4a 8b 0c de 49 89 c9 89 c9 49 c1 e9 20 49 89 c8 4c 0f af c5 4d 89 ca 4c 0f af d5 49 0f af cc 4c 89 c3 45 89 c0 48 c1 eb 20 49 01 c0 4d 0f af cc 4c 01 d1 48 01 d9 49 89 cf 49 c1 e7 20 4d 01 f8 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}