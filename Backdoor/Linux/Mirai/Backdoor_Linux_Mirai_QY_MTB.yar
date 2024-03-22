
rule Backdoor_Linux_Mirai_QY_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.QY!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {02 80 00 04 90 06 e0 28 03 00 00 10 c2 36 e0 06 c6 17 bf d6 } //01 00 
		$a_00_1 = {32 80 00 05 83 30 a0 10 c2 0e 40 00 b4 06 80 01 83 30 a0 10 07 00 00 3f 86 10 e3 ff } //01 00 
		$a_00_2 = {86 10 20 00 80 a0 c0 0b 32 80 00 05 90 02 20 01 81 c3 e0 08 90 10 20 01 90 02 20 01 } //00 00 
	condition:
		any of ($a_*)
 
}