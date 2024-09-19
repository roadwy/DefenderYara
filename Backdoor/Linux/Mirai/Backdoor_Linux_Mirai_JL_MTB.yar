
rule Backdoor_Linux_Mirai_JL_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.JL!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 54 28 21 00 53 20 21 02 15 10 2a 02 40 30 21 24 07 40 00 10 ?? ?? ?? 26 10 00 01 8c 84 00 00 8c a5 00 00 02 20 c8 21 03 20 f8 09 00 00 00 00 8f bc 00 10 10 ?? ?? ?? 00 10 10 80 } //1
		$a_03_1 = {30 c3 00 ff 24 62 ff d0 30 42 00 ff 2c 42 00 0a 14 ?? ?? ?? 24 62 ff bf 30 42 00 ff 2c 42 00 1a 10 ?? ?? ?? 24 62 ff 9f 24 02 00 37 10 ?? ?? ?? 00 c2 18 23 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}