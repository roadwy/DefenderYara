
rule Backdoor_Linux_Mirai_KG_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.KG!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {93 61 16 62 05 79 10 61 70 39 22 23 04 73 10 23 ec 73 02 e1 11 23 04 73 22 23 fb 7c f0 ?? 24 73 } //1
		$a_01_1 = {20 d0 0b 40 09 00 f8 7f 00 e1 12 20 0c e0 a2 2f fc 01 f6 56 1c 65 1b d1 b1 1f f4 57 0b 41 83 64 08 7f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}