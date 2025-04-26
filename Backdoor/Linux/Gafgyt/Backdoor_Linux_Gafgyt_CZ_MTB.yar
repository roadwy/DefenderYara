
rule Backdoor_Linux_Gafgyt_CZ_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.CZ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {03 99 e0 21 27 bd ff d0 af bf 00 2c af be 00 28 03 a0 f0 21 af bc 00 10 af c4 00 30 af c5 00 34 af c6 00 38 af c7 00 3c af c0 00 24 24 02 00 20 af c2 00 20 8f c2 00 38 } //1
		$a_00_1 = {af bf 00 2c af be 00 28 03 a0 f0 21 af bc 00 10 af c4 00 30 af c0 00 1c 8f c4 00 30 8f 99 81 84 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}