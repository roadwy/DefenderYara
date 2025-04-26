
rule Backdoor_Linux_Turla_G{
	meta:
		description = "Backdoor:Linux/Turla.G,SIGNATURE_TYPE_ELFHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 c1 c8 08 25 e0 01 00 00 c1 e0 11 41 81 e1 3f fc 3f fc 41 09 c1 89 d0 81 e2 00 80 00 00 25 80 03 00 00 c1 fa 06 d1 f8 } //5
		$a_01_1 = {66 c1 c8 08 89 c2 83 e0 07 81 e2 00 e0 00 00 c1 fa 0a } //5
		$a_01_2 = {25 c0 01 00 00 01 c0 81 e1 7f 7c 00 00 09 c1 89 f0 81 e6 00 00 c0 03 25 00 02 00 00 c1 ee 16 c1 e0 06 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=15
 
}