
rule Backdoor_Linux_Mirai_BU_xp{
	meta:
		description = "Backdoor:Linux/Mirai.BU!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {00 58 81 21 00 1c 88 09 00 00 2f 80 00 72 } //1
		$a_00_1 = {01 a4 89 23 00 0b 2f 89 00 2e 41 be ff e8 3f 40 10 03 55 29 08 3c 81 5a } //1
		$a_00_2 = {83 81 00 30 83 a1 00 34 83 c1 00 38 83 e1 00 3c 38 21 00 40 4e 80 00 20 88 1d 00 00 3b c0 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}