
rule Backdoor_Linux_Mirai_QX_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.QX!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {eb 08 8b 44 24 0c 66 c1 c8 08 66 89 46 02 } //1
		$a_00_1 = {c7 02 ff ff ff ff 8d 84 24 ec 2e 00 00 c7 42 04 00 00 00 00 c7 42 08 00 00 00 00 83 c2 0c 39 c2 75 de } //1
		$a_00_2 = {e8 a6 ff ff ff 83 eb 04 89 06 83 c6 04 eb 1f 83 fb 01 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}