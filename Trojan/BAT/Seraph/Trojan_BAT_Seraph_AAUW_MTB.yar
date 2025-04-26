
rule Trojan_BAT_Seraph_AAUW_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAUW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 66 65 69 6f 77 66 } //1 Hfeiowf
		$a_01_1 = {4c 67 69 72 6a 6f 67 } //1 Lgirjog
		$a_01_2 = {47 69 6a 72 67 } //1 Gijrg
		$a_01_3 = {57 65 67 66 69 6a 72 67 } //1 Wegfijrg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}