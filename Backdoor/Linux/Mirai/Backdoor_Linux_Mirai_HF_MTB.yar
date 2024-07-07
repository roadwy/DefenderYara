
rule Backdoor_Linux_Mirai_HF_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.HF!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2d 6e 00 1c ff d8 50 ae 00 1c 51 ae 00 20 72 0f b2 ae ff fc 90 01 02 70 22 2d 40 ff d0 60 00 90 01 02 2d 6e ff f8 ff dc 72 10 d3 ae ff f8 70 f0 d1 ae ff fc 72 07 b2 ae ff fc 90 01 02 70 22 2d 40 ff d0 90 00 } //1
		$a_03_1 = {20 6e ff f4 12 10 20 6e ff f8 10 10 b0 01 90 01 02 52 ae ff f8 20 6e ff f8 10 10 4a 00 90 01 02 20 6e ff f8 10 10 4a 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}