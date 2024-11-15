
rule Ransom_Linux_Babuk_N_MTB{
	meta:
		description = "Ransom:Linux/Babuk.N!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 48 83 ec 10 48 8b 7c 24 20 48 8b 74 24 28 48 8b 54 24 30 48 8b 05 12 26 12 00 48 89 e3 48 83 e4 f0 ff d0 48 89 dc 89 44 24 38 48 83 c4 10 5d c3 } //1
		$a_01_1 = {8b 7c 24 08 48 8b 74 24 10 48 c7 c2 00 00 00 00 49 c7 c2 00 00 00 00 49 c7 c0 00 00 00 00 4c 8b 6c 24 18 4c 8b 4c 24 20 4c 8b 64 24 28 49 83 fd 00 74 18 49 83 f9 00 74 12 4d 8d 85 88 00 00 00 49 83 c0 08 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}