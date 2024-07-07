
rule Backdoor_Linux_Tsunami_M_xp{
	meta:
		description = "Backdoor:Linux/Tsunami.M!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {00 19 00 44 00 12 30 00 00 10 38 00 00 21 28 a7 00 21 38 a0 00 18 80 82 8f 00 00 00 00 } //1
		$a_00_1 = {03 80 ef bd 27 7c 10 bf af 78 10 be af 21 f0 a0 03 10 00 bc af 02 00 04 24 01 00 05 24 21 30 00 00 5c 82 99 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}