
rule Trojan_Win32_CryptInject_FJC_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.FJC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_81_0 = {46 73 74 6e 69 6e 67 73 76 72 6b 65 72 6e 65 73 36 } //1 Fstningsvrkernes6
		$a_81_1 = {54 69 6c 6b 72 73 65 6c 73 72 61 6d 70 65 6e 35 } //1 Tilkrselsrampen5
		$a_81_2 = {56 69 6e 64 6d 6c 6c 65 70 72 6f 6a 65 6b 74 65 74 31 } //1 Vindmlleprojektet1
		$a_81_3 = {4b 75 6e 73 74 75 64 73 74 69 6c 6c 69 6e 67 65 72 36 } //1 Kunstudstillinger6
		$a_81_4 = {76 65 6e 74 72 6f 70 6f 73 74 65 72 69 6f 72 } //1 ventroposterior
		$a_81_5 = {73 65 6b 72 65 74 69 6f 6e 65 6e } //1 sekretionen
		$a_81_6 = {62 6f 62 69 6e 65 74 73 } //1 bobinets
		$a_81_7 = {53 4b 41 41 4e 45 50 52 4f 47 52 41 4d 4d 45 54 53 } //1 SKAANEPROGRAMMETS
		$a_81_8 = {49 4e 54 45 52 47 55 4c 41 52 } //1 INTERGULAR
		$a_81_9 = {73 61 6d 6d 65 6e 6c 69 67 6e 69 6e 67 73 6f 70 65 72 61 74 6f 72 65 72 6e 65 73 } //1 sammenligningsoperatorernes
		$a_81_10 = {65 6d 69 73 73 69 6f 6e 73 67 72 6e 73 65 76 72 64 69 65 72 } //1 emissionsgrnsevrdier
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=11
 
}