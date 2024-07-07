
rule Backdoor_Linux_Gafgyt_CT_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.CT!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {00 24 42 79 64 af c2 00 40 } //1
		$a_00_1 = {00 24 59 0a d0 03 20 f8 09 00 } //1
		$a_00_2 = {8f 82 80 20 00 00 00 00 24 59 07 dc 03 20 f8 09 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}