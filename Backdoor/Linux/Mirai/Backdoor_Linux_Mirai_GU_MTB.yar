
rule Backdoor_Linux_Mirai_GU_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.GU!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {a8 00 a7 8f 20 00 a2 af 10 00 a3 af 21 20 c0 02 21 28 00 00 09 f8 20 03 03 00 06 24 18 00 bc 8f 38 ?? ?? ?? 00 00 00 00 0d 00 85 92 00 00 00 00 47 ?? ?? ?? 20 00 a0 af 1c 80 93 8f 62 10 02 3c 3c 00 a3 27 d3 4d 52 34 21 80 00 00 7c 00 be 27 58 00 b5 27 ac 00 a3 af } //1
		$a_03_1 = {44 00 44 8c 10 00 43 8c 48 00 45 94 28 00 63 24 08 00 04 a2 ff ff 63 30 04 00 66 8e ff 00 62 30 ff 00 a4 30 00 12 02 00 00 22 04 00 02 1a 03 00 02 2a 05 00 4c 00 c7 8c 25 18 62 00 25 28 a4 00 02 00 03 a6 03 ?? ?? ?? 04 00 05 a6 40 00 02 24 06 00 02 a6 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}