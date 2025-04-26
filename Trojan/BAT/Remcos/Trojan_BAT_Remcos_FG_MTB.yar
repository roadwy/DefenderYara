
rule Trojan_BAT_Remcos_FG_MTB{
	meta:
		description = "Trojan:BAT/Remcos.FG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {44 61 76 69 64 65 20 48 6f 6d 65 70 61 67 65 } //1 Davide Homepage
		$a_81_1 = {64 61 76 69 64 65 6d 61 75 72 69 2e 69 74 } //1 davidemauri.it
		$a_81_2 = {72 65 67 65 78 6c 69 62 } //1 regexlib
		$a_81_3 = {48 6f 6c 79 20 53 68 69 74 } //1 Holy Shit
		$a_81_4 = {52 65 67 45 78 20 43 68 65 61 74 53 68 65 65 74 } //1 RegEx CheatSheet
		$a_81_5 = {43 53 68 61 72 70 53 6e 69 70 70 65 74 } //1 CSharpSnippet
		$a_81_6 = {6f 70 61 62 6c 6f 40 67 6d 61 69 6c 2e 63 6f 6d } //1 opablo@gmail.com
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}