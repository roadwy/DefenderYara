
rule Backdoor_Linux_Mirai_FE_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.FE!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {30 84 00 ff 18 ?? ?? ?? 30 c6 00 ff ?? a2 00 04 00 00 00 00 10 ?? ?? ?? 24 a3 00 08 10 ?? ?? ?? 00 00 40 21 ?? 62 00 04 00 00 00 00 10 ?? ?? ?? 24 63 00 08 } //1
		$a_03_1 = {00 04 18 c0 00 04 11 40 00 43 10 23 00 5e 28 21 8f a2 00 68 00 04 18 80 00 62 18 21 ?? a2 00 14 8c 71 00 00 2c 42 00 20 14 40 00 47 26 32 00 14 8f a3 00 28 24 02 ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}