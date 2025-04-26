
rule Trojan_BAT_Razy_DHB_MTB{
	meta:
		description = "Trojan:BAT/Razy.DHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 "
		
	strings :
		$a_81_0 = {6b 6a 76 73 68 6b 61 2e 2a 6b 6a 76 73 68 6b 61 } //1 kjvshka.*kjvshka
		$a_81_1 = {68 73 65 66 6c 6b 6a 73 65 6e 66 } //1 hseflkjsenf
		$a_81_2 = {73 6b 6a 76 6e 6c 73 6b 64 6a 6e 63 } //1 skjvnlskdjnc
		$a_81_3 = {61 69 6c 64 6b 6a 63 68 62 6c 61 6b 6a 73 63 } //1 aildkjchblakjsc
		$a_81_4 = {6c 71 61 6b 64 6a 63 68 62 6c 61 73 6b 6a 64 63 6e } //1 lqakdjchblaskjdcn
		$a_81_5 = {65 75 66 67 79 68 73 6f 75 79 65 68 74 38 33 } //1 eufgyhsouyeht83
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=2
 
}