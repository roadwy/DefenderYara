
rule Backdoor_Linux_Mirai_GF_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.GF!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 31 f6 53 48 89 fb 48 83 ec 08 e8 e5 e7 ff ff 48 8b 6b 10 48 89 df 48 c7 43 10 00 00 00 00 e8 7b e8 ff ff eb ?? 48 8b 5d 10 } //1
		$a_03_1 = {e8 a9 ff ff ff 48 89 44 24 10 48 8b 74 24 10 4c 89 e7 e8 3d e7 ff ff ?? ?? ?? ?? ?? 48 89 de e8 83 fe ff ff 4c 89 e7 89 c3 e8 d0 e7 ff ff 89 d8 48 83 c4 18 5b 41 5c c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}