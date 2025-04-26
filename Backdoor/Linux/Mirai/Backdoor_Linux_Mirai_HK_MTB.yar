
rule Backdoor_Linux_Mirai_HK_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.HK!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {53 ae ff f0 20 6e ff f0 1d 50 ff f9 53 ae ff ec 53 ae ff f4 20 6e ff ec 10 ae ff f9 4a ae ff f4 ?? ?? 70 03 c0 ae ff f0 4a 80 ?? ?? 20 2e 00 10 e4 88 22 2e ff f0 20 6e ff ec 2f 00 2f 01 2f 08 } //1
		$a_03_1 = {4a ae ff f0 56 c0 14 00 49 c2 2d 42 ff ec 20 2e ff ec 44 80 2d 40 ff ec 20 2e ff ec 4a 80 ?? ?? 20 6e ff f0 20 2e 00 08 20 80 20 2e ff f0 22 00 58 81 2d 41 ff f0 20 2e ff f0 20 40 24 2e ff d8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}