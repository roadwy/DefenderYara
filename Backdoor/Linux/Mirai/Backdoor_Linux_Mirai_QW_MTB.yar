
rule Backdoor_Linux_Mirai_QW_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.QW!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {0c 20 d4 e7 00 30 d0 e5 02 00 53 e1 01 c0 8c e2 00 c0 a0 13 03 00 00 1a 0e 00 5c e1 01 00 00 1a 01 00 a0 e3 10 80 bd e8 01 00 80 e2 01 10 51 e2 f2 ff ff 2a } //01 00 
		$a_00_1 = {e1 ff ff eb 04 40 94 e5 04 30 94 e5 00 00 53 e3 04 00 a0 e1 f9 ff ff 1a } //01 00 
		$a_00_2 = {04 30 d2 e7 00 00 53 e3 41 30 83 02 04 30 c2 07 01 20 82 e2 00 00 52 e1 10 80 bd 08 f7 ff ff ea 00 20 a0 e3 f5 ff ff ea } //00 00 
	condition:
		any of ($a_*)
 
}