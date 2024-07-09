
rule Backdoor_Linux_Mirai_GB_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.GB!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {61 ff 00 00 08 28 2d 40 ff f8 61 ff 00 00 07 a6 2d 40 ff fc 20 2e ff f8 b0 ae ff fc ?? ?? 70 01 2d 40 ff ec } //1
		$a_03_1 = {4e 56 ff ec 61 ff 00 00 08 8a 2d 40 ff f0 61 ff 00 00 08 08 2d 40 ff f4 20 2e ff f0 b0 ae ff f4 ?? ?? 70 01 2d 40 ff ec } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}