
rule Backdoor_Linux_Tori_B_xp{
	meta:
		description = "Backdoor:Linux/Tori.B!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {30 50 e2 05 10 a0 e1 03 20 a0 e1 06 00 a0 e1 03 40 84 e0 ef } //1
		$a_00_1 = {30 9a e5 07 01 84 e7 01 70 87 e2 07 00 53 e1 ec } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}