
rule Backdoor_Linux_Mirai_CJ_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.CJ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {83 25 23 e0 ae 39 2e e0 02 30 23 e0 22 c4 23 e0 ff 10 0c e2 2c 28 a0 e1 2c 34 a0 e1 00 00 51 e3 7f 00 51 13 ff 60 02 e2 ff 00 03 e2 2c 2c a0 e1 ee ff ff 0a 03 00 51 e3 ec ff ff 0a 0f 30 41 e2 38 00 51 e3 01 00 53 13 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}