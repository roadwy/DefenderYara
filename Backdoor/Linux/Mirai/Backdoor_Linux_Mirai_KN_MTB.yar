
rule Backdoor_Linux_Mirai_KN_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.KN!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 00 28 21 02 60 20 21 02 40 c8 21 03 20 f8 09 24 06 00 01 24 03 00 01 8f bc 00 10 14 ?? ?? ?? 02 20 10 21 26 31 00 01 02 34 10 2a 10 ?? ?? ?? 24 02 00 0a 82 03 00 } //1
		$a_03_1 = {81 28 00 00 80 47 00 00 25 03 ff bf 30 63 00 ff 24 e2 ff bf 30 42 00 ff 2c 63 00 1a 24 a5 ff ff 25 29 00 01 10 ?? ?? ?? 2c 42 00 1a 35 08 00 60 10 ?? ?? ?? 00 00 00 00 34 e7 00 60 11 ?? ?? ?? 25 4a 00 01 00 00 50 21 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}