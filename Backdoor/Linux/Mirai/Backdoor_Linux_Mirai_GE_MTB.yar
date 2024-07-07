
rule Backdoor_Linux_Mirai_GE_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.GE!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4e 56 ff dc 2f 02 20 2e 00 08 58 80 2d 40 00 08 2f 2e 00 10 61 ff 00 00 15 40 58 8f 20 0e 50 80 2f 00 2f 2e 00 0c 61 ff 00 00 06 ce 50 8f 20 08 2d 40 ff f0 2f 2e 00 10 61 ff 00 00 15 1c 58 8f 4a ae ff f0 57 c0 12 00 49 c1 2d 41 ff dc 20 2e ff dc 44 80 } //1
		$a_01_1 = {2d 6e ff e6 ff ea 2d 7c 7e fe fe ff ff f2 42 81 12 2e ff fb 42 80 10 2e ff fb e1 88 80 81 2d 40 ff f6 20 2e ff f6 48 40 42 40 81 ae ff f6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}