
rule Trojan_Win32_VBInject_AV_MSR{
	meta:
		description = "Trojan:Win32/VBInject.AV!MSR,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_80_0 = {43 72 65 61 74 6f 72 73 36 } //Creators6  1
		$a_80_1 = {41 74 6f 70 69 63 } //Atopic  1
		$a_80_2 = {63 6c 75 73 74 65 72 69 6e 67 } //clustering  1
		$a_80_3 = {61 70 69 61 72 79 } //apiary  1
		$a_80_4 = {65 78 70 6f 75 6e 64 65 64 } //expounded  1
		$a_80_5 = {43 69 76 69 6c 69 7a 61 62 6c 65 } //Civilizable  1
		$a_80_6 = {61 6d 69 63 61 62 69 6c 69 74 69 65 73 } //amicabilities  1
		$a_80_7 = {63 6f 6d 70 75 74 65 72 69 7a 65 73 } //computerizes  1
		$a_80_8 = {73 63 61 73 73 69 } //scassi  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=9
 
}