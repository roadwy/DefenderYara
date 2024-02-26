
rule Backdoor_Linux_Mirai_KL_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.KL!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {92 10 00 02 80 a2 80 01 02 80 00 08 84 00 a0 08 86 00 e0 01 80 a2 00 03 32 bf ff fa } //01 00 
		$a_00_1 = {18 80 00 04 80 a6 60 04 81 c7 e0 08 81 e8 00 00 02 bf ff fe } //01 00 
		$a_00_2 = {86 00 7f 54 82 00 60 04 80 a0 60 80 12 bf ff fd } //00 00 
	condition:
		any of ($a_*)
 
}