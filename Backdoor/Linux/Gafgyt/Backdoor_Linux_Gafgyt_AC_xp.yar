
rule Backdoor_Linux_Gafgyt_AC_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.AC!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 54 53 49 54 53 4c 54 53 4c 54 53 41 54 53 54 54 53 54 54 53 4b } //1 KTSITSLTSLTSATSTTSTTSK
		$a_01_1 = {55 54 53 44 54 53 50 } //1 UTSDTSP
		$a_01_2 = {4c 54 53 4f 54 53 4c 54 53 4e 54 53 4f 54 53 47 54 53 54 54 53 46 54 53 4f } //1 LTSOTSLTSNTSOTSGTSTTSFTSO
		$a_01_3 = {4a 54 53 55 54 53 4e 54 53 4b } //1 JTSUTSNTSK
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}