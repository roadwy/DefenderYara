
rule Backdoor_Linux_Mirai_IK_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.IK!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {7c 08 02 a6 94 21 ff f0 7c 64 1b 78 38 60 00 01 90 01 00 14 4c c6 31 82 48 00 03 25 80 01 00 14 38 21 00 10 7c 08 03 a6 4e 80 00 20 } //01 00 
		$a_01_1 = {94 21 ff e0 7c 08 02 a6 90 61 00 08 38 60 00 66 90 81 00 0c 38 80 00 03 90 a1 00 10 38 a1 00 08 90 01 00 24 4c c6 31 82 48 00 02 85 80 01 00 24 38 21 00 20 7c 08 03 a6 4e 80 00 20 } //00 00 
	condition:
		any of ($a_*)
 
}