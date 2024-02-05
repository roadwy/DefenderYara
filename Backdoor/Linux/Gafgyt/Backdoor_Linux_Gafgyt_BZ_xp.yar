
rule Backdoor_Linux_Gafgyt_BZ_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.BZ!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {bf e0 c2 07 bf e0 87 30 60 00 84 10 20 00 84 10 00 03 03 00 00 c5 } //01 00 
		$a_00_1 = {00 80 01 c2 08 40 00 83 28 60 18 83 38 60 18 90 10 00 01 40 00 2b d4 01 00 } //00 00 
	condition:
		any of ($a_*)
 
}