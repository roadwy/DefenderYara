
rule Backdoor_Linux_Mirai_AR_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.AR!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {00 ea 04 30 dc e5 02 00 53 e1 08 c0 8c e2 06 00 00 0a 01 e0 8e e2 0e 00 50 e1 0c 10 a0 e1 f7 ff ff 1a 04 00 a0 e1 10 40 bd e8 1e ff 2f } //00 00 
	condition:
		any of ($a_*)
 
}