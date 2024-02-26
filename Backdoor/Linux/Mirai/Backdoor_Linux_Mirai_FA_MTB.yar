
rule Backdoor_Linux_Mirai_FA_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.FA!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {10 73 00 55 24 02 00 09 10 62 00 53 24 02 00 01 10 e2 00 47 00 00 00 00 00 00 38 21 28 a2 00 07 10 40 00 05 24 84 00 01 80 83 00 00 24 c6 00 01 14 60 ff f3 } //01 00 
		$a_00_1 = {73 6f 6d 65 6f 66 66 64 65 65 7a 6e 75 74 73 } //00 00  someoffdeeznuts
	condition:
		any of ($a_*)
 
}