
rule Backdoor_Linux_Gafgyt_AF_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.AF!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 54 53 49 54 53 4c 54 53 4c 54 53 41 54 53 54 54 53 54 54 53 4b } //01 00  KTSITSLTSLTSATSTTSTTSK
		$a_01_1 = {4c 54 53 4f 54 53 4c 54 53 4e 54 53 4f 54 53 47 54 53 54 54 53 46 54 53 4f } //01 00  LTSOTSLTSNTSOTSGTSTTSFTSO
		$a_01_2 = {55 54 53 44 54 53 50 } //00 00  UTSDTSP
		$a_00_3 = {5d 04 00 } //00 66 
	condition:
		any of ($a_*)
 
}