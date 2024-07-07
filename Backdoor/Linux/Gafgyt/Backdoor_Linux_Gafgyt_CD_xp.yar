
rule Backdoor_Linux_Gafgyt_CD_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.CD!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {20 9f e5 04 30 82 e5 14 30 1b e5 3d 34 83 e2 91 38 43 e2 32 3d 43 e2 0e 30 43 e2 74 20 9f e5 08 30 82 e5 03 } //1
		$a_00_1 = {30 83 e2 18 30 0b e5 00 30 a0 e3 28 30 0b e5 28 20 1b e5 2c 20 0b e5 18 30 1b e5 00 30 d3 e5 00 00 53 e3 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}