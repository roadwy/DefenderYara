
rule Backdoor_Linux_Turla_C{
	meta:
		description = "Backdoor:Linux/Turla.C,SIGNATURE_TYPE_ELFHSTR_EXT,19 00 19 00 05 00 00 "
		
	strings :
		$a_80_0 = {5f 5f 5f 31 32 33 21 40 23 } //___123!@#  5
		$a_80_1 = {5f 5f 5f 34 35 36 24 24 24 } //___456$$$  5
		$a_01_2 = {8b 01 83 c1 04 8d 90 ff fe fe fe f7 d0 21 c2 81 e2 80 80 80 80 74 e9 } //5
		$a_80_3 = {5f 5f 77 65 5f 61 72 65 5f 68 61 70 70 79 5f 5f } //__we_are_happy__  10
		$a_01_4 = {c7 85 e8 af ff ff 5f 5f 77 65 c7 85 ec af ff ff 5f 61 72 65 c7 85 f0 af ff ff 5f 68 61 70 c7 85 f4 af ff ff 70 79 5f 5f } //10
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*5+(#a_01_2  & 1)*5+(#a_80_3  & 1)*10+(#a_01_4  & 1)*10) >=25
 
}