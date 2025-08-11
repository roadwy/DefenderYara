
rule Backdoor_Linux_Mirai_KY_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.KY!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8f 99 83 6c 27 a4 00 18 24 05 00 01 12 00 00 08 02 40 30 21 03 20 f8 09 00 00 00 00 24 03 00 01 8f bc 00 10 10 43 ff f6 26 10 ff ff 26 10 00 01 02 30 10 23 8f bf 00 2c 8f b2 00 28 8f b1 00 24 8f b0 00 20 03 e0 00 08 27 bd 00 30 } //1
		$a_01_1 = {82 03 00 00 00 00 00 00 10 60 00 03 24 02 00 25 14 62 ff fa 00 00 00 00 12 04 00 0c 02 04 88 23 1e 20 00 03 02 20 28 21 10 00 00 06 00 00 10 21 8f 99 83 6c 00 00 00 00 03 20 f8 09 02 c0 30 21 8f bc 00 18 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}