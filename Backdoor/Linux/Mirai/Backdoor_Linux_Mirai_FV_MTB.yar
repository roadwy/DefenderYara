
rule Backdoor_Linux_Mirai_FV_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.FV!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 40 d1 d1 bb 10 20 40 d1 d1 b9 10 20 40 d1 d1 b7 10 20 40 d1 d1 b5 10 52 80 42 81 32 29 00 04 b0 81 } //1
		$a_03_1 = {20 6e 00 08 30 10 00 40 00 08 22 6e 00 08 32 80 20 6e 00 08 20 28 00 0c 22 00 22 6e 00 08 20 29 00 08 24 01 94 80 2d 42 ff f8 4a ae ff f8 90 01 02 20 2e ff f8 b0 ae ff f0 90 01 02 2d 6e ff f0 ff f8 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}