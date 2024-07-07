
rule Trojan_BAT_Njrat_DA_MTB{
	meta:
		description = "Trojan:BAT/Njrat.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_81_0 = {24 24 24 24 24 24 24 69 24 24 24 24 6e 24 24 24 76 24 24 24 24 6f 24 24 24 6b 24 24 24 65 24 24 24 24 24 24 24 24 24 } //10 $$$$$$$i$$$$n$$$v$$$$o$$$k$$$e$$$$$$$$$
		$a_81_1 = {57 69 6e 64 6f 77 73 41 70 70 6c 69 63 61 74 69 6f 6e } //1 WindowsApplication
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_3 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_81_4 = {43 6f 6e 76 65 72 74 } //1 Convert
		$a_81_5 = {45 6e 74 72 79 50 6f 69 6e 74 } //1 EntryPoint
		$a_81_6 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=16
 
}