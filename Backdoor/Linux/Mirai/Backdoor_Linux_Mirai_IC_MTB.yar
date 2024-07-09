
rule Backdoor_Linux_Mirai_IC_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.IC!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {45 31 e4 f6 07 40 74 ?? e8 f4 fc ff ff 41 83 cc ff 48 85 c0 75 ?? 48 8b 43 08 66 83 23 bf 45 31 e4 48 89 43 30 48 83 c4 28 44 89 e0 } //1
		$a_03_1 = {48 8b 45 18 48 3b 45 28 73 ?? 8a 10 48 ff c0 88 13 48 ff c3 80 fa 0a 48 89 45 18 eb ?? 48 89 ef e8 df fe ff ff 83 f8 ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}