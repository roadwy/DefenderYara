
rule Backdoor_Linux_Mirai_KW_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.KW!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {42 04 00 71 40 01 00 54 23 04 1a 12 7f 00 03 71 61 00 00 54 00 08 00 91 } //1
		$a_01_1 = {5f 00 00 6b 4a fc ff 54 24 68 60 38 23 68 62 38 24 68 22 38 42 04 00 91 23 68 20 38 00 04 00 d1 f8 ff ff 17 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}