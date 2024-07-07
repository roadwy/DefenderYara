
rule Backdoor_Linux_Gafgyt_CG_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.CG!xp,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {41 57 41 56 41 55 41 89 fd 41 54 44 0f b6 e2 ba 15 00 00 00 44 89 e7 55 53 48 89 cb 31 c9 48 81 ec c8 51 00 00 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}