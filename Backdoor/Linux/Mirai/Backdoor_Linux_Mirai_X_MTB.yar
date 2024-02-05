
rule Backdoor_Linux_Mirai_X_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.X!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {04 00 a0 e1 90 01 01 01 00 eb 01 00 80 e2 90 01 01 02 00 eb 04 10 a0 e1 07 00 85 e7 90 01 01 01 00 eb 00 00 a0 e3 90 01 02 9f e5 90 01 02 00 eb 00 40 50 e2 01 60 86 e2 04 50 85 e2 f1 ff ff 1a 90 00 } //01 00 
		$a_00_1 = {03 10 96 e7 5c 30 9d e5 00 00 52 e3 01 2a a0 03 01 00 73 e3 00 20 81 e5 09 00 00 1a dc 00 00 eb 00 40 a0 e1 f1 00 00 eb 00 00 54 e1 0e 00 00 1a 0e 01 00 eb 00 40 a0 e1 e7 00 00 eb 00 00 54 e1 09 00 00 1a } //00 00 
	condition:
		any of ($a_*)
 
}