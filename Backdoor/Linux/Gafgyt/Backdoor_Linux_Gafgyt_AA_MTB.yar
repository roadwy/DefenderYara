
rule Backdoor_Linux_Gafgyt_AA_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.AA!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_00_0 = {00 21 30 40 00 78 82 99 8f 00 } //00 00 
	condition:
		any of ($a_*)
 
}