
rule Backdoor_Linux_Mirai_IW_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.IW!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {10 00 00 05 24 c6 ff ff 90 a2 00 00 24 a5 00 01 a0 82 00 00 24 84 00 01 24 02 ff ff 14 c2 ff fa 24 c6 ff ff 03 e0 00 08 00 00 00 00 } //1
		$a_00_1 = {00 00 00 00 13 23 00 08 24 50 ff fc 03 20 f8 09 26 10 ff fc 8e 19 00 00 24 02 ff ff 8f bc 00 10 17 22 ff fa 00 00 00 00 8f bf 00 1c 8f b0 00 18 03 e0 00 08 27 bd 00 20 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}