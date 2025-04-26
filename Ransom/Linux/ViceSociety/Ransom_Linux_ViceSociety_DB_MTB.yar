
rule Ransom_Linux_ViceSociety_DB_MTB{
	meta:
		description = "Ransom:Linux/ViceSociety.DB!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 76 2d 73 6f 63 69 65 74 79 } //1 .v-society
		$a_01_1 = {55 73 61 67 65 3a 25 73 20 5b 2d 6d 20 28 31 30 2d 32 30 2d 32 35 2d 33 33 2d 35 30 29 20 5d 20 53 74 61 72 74 20 50 61 74 68 } //1 Usage:%s [-m (10-20-25-33-50) ] Start Path
		$a_00_2 = {48 8d 85 f0 ef ff ff 48 89 c7 e8 b0 1e 00 00 89 85 54 ef ff ff 83 bd 54 ef ff ff 00 0f 84 c0 01 00 00 48 8b 05 c3 84 20 00 48 85 c0 74 28 48 8b 05 b7 84 20 00 8b 8d 54 ef ff ff 48 8d 95 f0 ef ff ff 48 8d 35 44 4d 00 00 48 89 c7 b8 } //1
		$a_00_3 = {48 8b 95 60 ef ff ff 48 8d 85 f0 ef ff ff 48 89 d6 48 89 c7 e8 91 ec ff ff 85 c0 0f 95 c0 84 c0 0f 84 af 00 00 00 48 8b 05 dd 82 20 00 48 85 c0 74 29 48 8b 05 d1 82 20 00 48 8b 8d 60 ef ff ff 48 8d 95 f0 ef ff ff 48 8d 35 a4 4b 00 00 48 89 c7 b8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}