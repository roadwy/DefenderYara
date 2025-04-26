
rule Backdoor_Linux_Mirai_EY_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.EY!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {49 83 ec 01 72 20 4d 8b 7d f8 49 8b 6d 00 4c 89 ff ff 55 00 48 8b 75 08 4c 89 ff e8 3d 01 00 00 49 83 c5 10 eb da } //1
		$a_00_1 = {74 10 48 8b b3 c0 00 00 00 48 c1 e6 02 e8 03 01 00 00 8b 7b 18 } //1
		$a_00_2 = {48 89 df e8 aa 6f 01 00 a8 01 74 17 49 8d 4e 01 48 8b 44 24 28 42 88 14 30 49 89 ce 49 ff cf 75 df } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}