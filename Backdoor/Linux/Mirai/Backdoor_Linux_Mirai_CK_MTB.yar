
rule Backdoor_Linux_Mirai_CK_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.CK!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {70 40 2d e9 04 d0 4d e2 90 01 02 00 eb 01 00 70 e3 00 30 a0 13 01 30 a0 03 00 00 50 e3 01 30 83 c3 98 28 9f e5 00 00 53 e3 00 00 82 e5 01 00 00 0a 90 00 } //01 00 
		$a_03_1 = {00 40 a0 e3 01 0b 8d e2 08 00 80 e2 90 01 02 00 eb 01 1b 8d e2 00 20 a0 e1 08 10 81 e2 06 00 a0 e1 01 40 84 e2 01 39 a0 e3 90 01 02 00 eb 19 00 54 e3 f3 ff ff 1a 06 00 a0 e1 05 10 a0 e1 01 2b a0 e3 01 39 a0 e3 90 01 02 00 eb 00 00 50 e3 eb ff ff 1a 06 00 a0 e1 90 01 02 00 eb 6f ff ff ea 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}