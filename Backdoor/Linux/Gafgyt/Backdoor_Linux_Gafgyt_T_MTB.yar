
rule Backdoor_Linux_Gafgyt_T_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.T!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {dc 00 10 00 40 20 21 3c 02 53 97 34 42 82 9d 00 82 00 19 00 00 10 10 00 02 11 02 af c2 01 68 8f } //1
		$a_03_1 = {ff 42 30 92 00 c2 a7 1c 00 c0 af 18 80 82 8f a0 00 c3 27 ?? ?? 42 24 c4 00 06 24 21 20 60 00 21 28 40 00 64 84 99 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}