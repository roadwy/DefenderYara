
rule Backdoor_Linux_Turla_M{
	meta:
		description = "Backdoor:Linux/Turla.M,SIGNATURE_TYPE_ELFHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_01_0 = {81 e2 e0 01 00 00 c1 e2 11 81 e3 3f fc 3f fc 09 d3 89 ca 81 e1 00 80 00 00 81 e2 80 03 00 00 c1 f9 06 d1 fa } //5
		$a_01_1 = {66 c1 c9 08 89 ca 81 e1 00 e0 00 00 83 e2 07 c1 f9 0a } //5
		$a_01_2 = {25 c0 01 00 00 81 e2 00 02 00 00 01 c0 81 e6 7f 7c 00 00 c1 e2 06 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=15
 
}