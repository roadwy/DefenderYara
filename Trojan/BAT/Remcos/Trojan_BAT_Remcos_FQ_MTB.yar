
rule Trojan_BAT_Remcos_FQ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.FQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_81_0 = {00 58 58 58 58 58 58 58 58 58 58 58 58 58 00 } //1
		$a_81_1 = {67 6e 69 72 74 53 34 36 65 73 61 42 6d 6f 72 46 } //1 gnirtS46esaBmorF
		$a_81_2 = {74 72 65 76 6e 6f 43 2e 6d 65 74 73 79 53 } //1 trevnoC.metsyS
		$a_81_3 = {49 52 6e 52 76 52 6f 52 6b 52 65 } //1 IRnRvRoRkRe
		$a_81_4 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_6 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=6
 
}