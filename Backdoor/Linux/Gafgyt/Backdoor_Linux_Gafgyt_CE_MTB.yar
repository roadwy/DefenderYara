
rule Backdoor_Linux_Gafgyt_CE_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.CE!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {10 00 dc 8f 21 20 40 00 97 53 02 3c 9d 82 42 34 19 00 82 00 10 10 00 00 02 11 02 00 68 01 c2 af 68 01 c2 8f } //1
		$a_00_1 = {18 00 dc 8f 21 20 40 00 55 55 02 3c 56 55 42 34 18 00 82 00 10 18 00 00 c3 17 04 00 23 18 62 00 44 02 c3 af 44 02 c2 8f } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}