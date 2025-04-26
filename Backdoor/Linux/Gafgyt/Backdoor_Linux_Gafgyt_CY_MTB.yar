
rule Backdoor_Linux_Gafgyt_CY_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.CY!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {62 18 26 3c 02 9e 37 34 42 79 b9 00 62 20 26 8f 82 80 18 00 06 18 80 24 42 68 c8 00 62 10 21 ac 44 00 00 8f c2 00 08 } //1
		$a_00_1 = {bd ff b8 af bf 00 44 af be 00 40 03 a0 f0 21 af bc 00 10 af c4 00 48 af c5 00 4c af c6 00 50 af c7 00 54 af c0 00 30 af c0 00 2c 8f c2 00 4c } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}