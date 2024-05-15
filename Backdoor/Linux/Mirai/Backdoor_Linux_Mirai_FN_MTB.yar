
rule Backdoor_Linux_Mirai_FN_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.FN!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {18 30 a0 e3 92 a3 28 e0 00 30 d4 e5 b0 30 c3 e3 40 30 83 e3 00 30 c4 e5 09 e8 a0 e1 00 30 d4 e5 42 c8 8e e2 2c 24 a0 e1 } //01 00 
		$a_03_1 = {05 00 51 e1 05 10 a0 21 00 30 d6 e5 0a 00 53 e3 01 60 86 e2 00 30 c2 e5 02 90 01 03 b0 30 d4 e1 01 0c 13 e3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}