
rule Backdoor_Linux_Mirai_FI_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.FI!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {42 ae ff ec 20 2e 00 10 55 80 72 22 b2 80 65 00 90 01 02 22 2e 00 10 70 ff 24 00 4c 41 20 00 1d 40 ff fb 20 2e 00 10 74 ff 4c 40 20 01 20 02 2d 40 ff f0 60 00 00 02 90 00 } //1
		$a_03_1 = {4a ae ff f8 90 01 02 48 78 00 11 20 0e 06 80 ff ff ff 60 2f 00 61 ff ff ff f0 a4 50 8f 4a 80 90 01 02 70 ff 2d 40 fe 4c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}