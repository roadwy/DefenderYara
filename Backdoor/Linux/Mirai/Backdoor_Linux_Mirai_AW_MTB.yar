
rule Backdoor_Linux_Mirai_AW_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.AW!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_00_0 = {8b 19 89 d0 01 d8 89 eb 30 18 89 d0 8b 19 01 d8 89 fb 30 18 89 d0 8b 19 01 d8 89 f3 30 18 89 d0 8b 19 42 01 d8 8a 1c 24 30 18 8b 41 04 25 ff ff 00 00 39 d0 } //2
	condition:
		((#a_00_0  & 1)*2) >=2
 
}