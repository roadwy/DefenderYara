
rule Backdoor_Linux_Mirai_FX_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.FX!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {05 00 a0 e1 7c ff ff eb 07 00 a0 e1 7a ff ff eb 38 10 9f e5 04 20 a0 e3 01 00 a0 e3 8b ff ff eb 05 00 a0 e3 70 ff ff eb 94 d0 8d e2 f0 81 bd e8 } //01 00 
		$a_03_1 = {8a ff ff 1b 93 30 dd e5 04 44 83 e1 7c 30 9f e5 03 00 54 e1 f3 90 01 03 0d 10 a0 e1 80 20 a0 e3 05 00 a0 e1 a1 ff ff eb 00 20 50 e2 0d 40 a0 e1 0d 10 a0 e1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}