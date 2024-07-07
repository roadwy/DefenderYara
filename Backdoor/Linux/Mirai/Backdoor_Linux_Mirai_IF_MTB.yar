
rule Backdoor_Linux_Mirai_IF_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.IF!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {18 00 a2 27 f0 82 99 8f c0 20 04 00 21 20 44 00 21 28 00 02 09 f8 20 03 08 00 06 24 10 00 bc 8f 08 00 10 26 00 00 04 8e } //1
		$a_03_1 = {2a 10 71 00 20 00 a2 34 ff 00 43 30 61 00 62 2c 03 90 01 03 a9 ff 62 24 02 90 01 03 28 00 03 24 ff 00 43 30 2a 10 71 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}