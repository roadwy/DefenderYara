
rule Backdoor_Linux_Mirai_EX_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.EX!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {04 00 42 92 00 00 43 8e 05 00 52 26 14 00 a2 a0 04 00 a3 ac 10 00 a3 ac 00 00 a6 a4 f8 ff 92 14 18 00 a5 24 21 10 d7 02 23 10 22 02 fa ff 54 24 } //1
		$a_03_1 = {21 10 43 02 00 00 42 80 00 00 00 00 ec ff 40 10 00 00 00 00 ?? ?? ?? ?? 01 00 63 24 ff ff 63 24 03 00 71 24 02 00 66 24 21 10 a6 02 20 00 43 80 00 00 00 00 c8 01 60 10 20 00 02 24 c5 01 62 10 01 00 c2 24 21 10 42 02 21 20 c0 00 03 00 00 10 20 00 05 24 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}