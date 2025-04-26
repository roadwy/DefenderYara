
rule Backdoor_Linux_Mirai_IH_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.IH!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8f 99 80 64 8e 44 00 04 03 20 f8 09 02 20 28 21 8f bc 00 10 04 ?? ?? ?? 00 00 00 00 02 22 88 21 10 ?? ?? ?? 02 02 80 23 96 42 00 00 8e 44 00 08 8e 43 00 0c 34 42 00 08 00 64 18 23 } //1
		$a_01_1 = {96 02 00 10 8e 03 00 04 8e 07 00 0c 92 08 00 12 30 46 ff ff ae 03 00 00 ae 07 00 04 a2 08 00 0a a6 02 00 08 03 20 f8 09 24 c6 ff ed 8f bc 00 10 96 06 00 08 8f 99 80 60 02 00 20 21 03 20 f8 09 02 00 28 21 96 02 00 08 8f bc 00 10 02 02 80 21 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}