
rule Backdoor_Linux_Mirai_GD_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.GD!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8f 82 80 70 8f 99 80 70 10 40 00 04 00 00 00 00 8f bf 00 18 03 20 00 08 27 bd 00 20 8f bf 00 18 00 00 00 00 03 e0 00 08 27 bd 00 20 } //1
		$a_00_1 = {16 60 00 07 02 00 10 21 8f 99 88 b4 27 a4 00 20 03 20 f8 09 24 05 00 01 8f bc 00 10 02 00 10 21 8f bf 00 40 8f b3 00 3c 8f b2 00 38 8f b1 00 34 8f b0 00 30 03 e0 00 08 27 bd 00 48 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}