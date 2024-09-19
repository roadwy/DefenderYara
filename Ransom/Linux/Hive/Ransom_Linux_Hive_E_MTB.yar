
rule Ransom_Linux_Hive_E_MTB{
	meta:
		description = "Ransom:Linux/Hive.E!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {ff 15 85 69 26 00 8b 30 48 85 f6 0f 84 48 01 00 00 48 c1 e6 20 48 83 ce 02 48 8d 8c 24 80 00 00 00 ba 01 00 00 00 31 c0 48 89 f3 4c 8b 74 24 70 48 8b 6c 24 68 44 8a 6c 24 06 4c 8b 64 24 60 eb 23 } //1
		$a_00_1 = {eb 40 ff 15 4b 48 26 00 8b 38 48 89 fb 48 c1 e3 20 48 83 cb 02 48 89 9c 24 b0 00 00 00 48 c7 84 24 a8 00 00 00 01 00 00 00 e8 6d c7 02 00 3c 23 75 4d 48 8d bc 24 b0 00 00 00 e8 cc 1b 00 00 4c 89 f9 48 85 c9 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}