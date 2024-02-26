
rule Trojan_BAT_Njrat_DA_MTB{
	meta:
		description = "Trojan:BAT/Njrat.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 0a 00 "
		
	strings :
		$a_81_0 = {24 24 24 24 24 24 24 69 24 24 24 24 6e 24 24 24 76 24 24 24 24 6f 24 24 24 6b 24 24 24 65 24 24 24 24 24 24 24 24 24 } //01 00  $$$$$$$i$$$$n$$$v$$$$o$$$k$$$e$$$$$$$$$
		$a_81_1 = {57 69 6e 64 6f 77 73 41 70 70 6c 69 63 61 74 69 6f 6e } //01 00  WindowsApplication
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_3 = {41 63 74 69 76 61 74 6f 72 } //01 00  Activator
		$a_81_4 = {43 6f 6e 76 65 72 74 } //01 00  Convert
		$a_81_5 = {45 6e 74 72 79 50 6f 69 6e 74 } //01 00  EntryPoint
		$a_81_6 = {52 65 70 6c 61 63 65 } //00 00  Replace
	condition:
		any of ($a_*)
 
}