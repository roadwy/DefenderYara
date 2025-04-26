
rule Backdoor_Linux_Mirai_GY_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.GY!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {21 e0 99 03 d8 ff bd 27 20 00 bf af 1c 00 b1 af 18 00 b0 af 10 00 bc af 21 80 a0 00 30 80 99 8f 21 88 80 00 21 28 00 00 21 20 00 02 09 f8 20 03 98 00 06 24 00 00 22 8e 10 00 bc 8f 04 00 00 ae 00 00 02 ae 10 00 22 8e } //1
		$a_03_1 = {ff ff 4a 25 00 00 42 a1 ff ff c6 24 fb ?? ?? ?? ff ff a5 24 01 00 a5 24 21 10 00 02 1c 00 bf 8f 18 00 b0 8f 08 00 e0 03 20 00 bd 27 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}