
rule Backdoor_Linux_Mirai_IM_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.IM!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 a0 60 07 32 90 01 03 92 02 60 20 e4 02 60 1c e6 02 60 14 80 a4 80 19 ec 02 60 10 ea 02 60 08 18 90 01 03 a8 10 00 12 10 90 01 03 a8 10 00 19 c2 00 c0 00 83 28 60 05 82 00 80 01 80 a2 40 01 90 00 } //01 00 
		$a_03_1 = {84 89 20 ff 02 90 01 03 c6 0a 40 00 82 08 e0 ff 80 a0 80 01 22 90 01 03 90 01 01 02 20 01 82 08 e0 ff 81 c3 e0 08 90 01 01 20 80 01 92 02 60 01 94 02 bf ff 80 a2 a0 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}