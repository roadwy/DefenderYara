
rule Ransom_Linux_Akira_AB_MTB{
	meta:
		description = "Ransom:Linux/Akira.AB!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {b8 c8 e4 91 00 c6 00 01 bf b8 e4 91 00 e8 7f f2 f6 ff ba e8 bc 64 00 be b8 e4 91 00 bf 62 57 46 00 e8 9f 61 0f 00 b8 d0 e4 91 00 } //1
		$a_01_1 = {55 48 89 e5 48 83 ec 10 48 89 7d f8 48 89 75 f0 48 8b 45 f8 48 89 c7 e8 0d 37 fd ff 84 c0 74 13 48 8b 55 f0 48 8b 45 f8 48 89 d6 48 89 c7 e8 03 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}