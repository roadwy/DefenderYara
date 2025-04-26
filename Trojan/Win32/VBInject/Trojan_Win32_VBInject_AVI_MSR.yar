
rule Trojan_Win32_VBInject_AVI_MSR{
	meta:
		description = "Trojan:Win32/VBInject.AVI!MSR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {43 6c 69 74 6f 72 69 64 65 61 6e 34 } //1 Clitoridean4
		$a_81_1 = {41 64 73 6f 72 62 65 64 } //1 Adsorbed
		$a_81_2 = {61 6c 70 68 61 62 65 74 69 7a 61 74 69 6f 6e } //1 alphabetization
		$a_81_3 = {44 65 73 6f 6c 61 74 65 6e 65 73 73 } //1 Desolateness
		$a_81_4 = {41 70 6f 63 72 79 70 68 61 6c 6e 65 73 73 } //1 Apocryphalness
		$a_81_5 = {70 61 77 65 72 } //1 pawer
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}