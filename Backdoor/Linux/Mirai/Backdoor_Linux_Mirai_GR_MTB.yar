
rule Backdoor_Linux_Mirai_GR_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.GR!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {05 00 1c 3c f4 84 9c 27 21 e0 99 03 d0 ff bd 27 28 00 bf af 10 00 bc af 5c 80 99 8f 18 00 a4 af 1c 00 a5 af 20 00 a6 af 06 10 04 24 18 00 a6 27 09 f8 20 03 03 00 05 24 10 00 bc 8f 28 00 bf 8f ?? ?? ?? ?? 08 00 e0 03 30 00 bd 27 } //1
		$a_01_1 = {05 00 1c 3c 1c 85 9c 27 21 e0 99 03 21 10 a0 00 5c 80 99 8f 21 38 c0 00 21 28 80 00 21 30 40 00 08 00 20 03 a5 0f 04 24 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}