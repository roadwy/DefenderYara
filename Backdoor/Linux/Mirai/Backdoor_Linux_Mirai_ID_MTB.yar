
rule Backdoor_Linux_Mirai_ID_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.ID!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {57 56 8b 4c 24 10 8b 54 24 14 8b 74 24 18 8b 7c 24 1c 8b 44 24 0c 53 89 c3 b8 ac 00 00 00 cd 80 5b 89 c2 81 fa 00 f0 ff ff 76 ?? b8 f8 ff ff ff f7 da 65 89 10 83 c8 ff } //1
		$a_03_1 = {b8 42 00 00 00 cd 80 89 c2 81 fa 00 f0 ff ff 76 ?? b8 f8 ff ff ff f7 da 65 89 10 83 c8 ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}