
rule Backdoor_Linux_Mirai_FW_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.FW!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {04 00 42 92 00 00 43 8e 05 00 52 26 14 00 a2 a0 04 00 a3 ac 10 00 a3 ac 00 00 a6 a4 f8 ?? ?? ?? 18 00 a5 24 21 10 d7 02 23 10 22 02 fa ff 54 24 } //1
		$a_01_1 = {02 1a 15 00 18 00 bc 8f 00 ff 63 30 00 ff a5 32 02 26 15 00 00 00 40 ac 00 36 15 00 25 20 83 00 24 00 a2 8f 28 00 a3 8f 00 2a 05 00 25 28 a6 00 f4 81 99 8f 20 00 a7 8f 25 20 85 00 10 00 b6 af 14 00 a2 af ff 00 65 30 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}