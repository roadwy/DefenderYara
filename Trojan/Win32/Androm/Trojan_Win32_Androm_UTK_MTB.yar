
rule Trojan_Win32_Androm_UTK_MTB{
	meta:
		description = "Trojan:Win32/Androm.UTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {41 70 6f 63 61 74 61 73 74 61 73 69 73 } //1 Apocatastasis
		$a_81_1 = {4d 61 73 6b 69 6e 73 6b 72 69 76 6e 69 6e 67 } //1 Maskinskrivning
		$a_81_2 = {49 64 65 6e 74 69 74 65 74 73 6d 72 6b 65 72 6e 65 73 } //1 Identitetsmrkernes
		$a_81_3 = {53 74 72 65 6e 67 74 68 66 75 6c 6e 65 73 73 36 } //1 Strengthfulness6
		$a_81_4 = {55 6e 63 6f 6e 63 65 70 74 75 61 6c 69 7a 65 64 33 } //1 Unconceptualized3
		$a_81_5 = {42 45 5a 50 4f 50 4f 56 45 54 53 } //1 BEZPOPOVETS
		$a_81_6 = {48 4f 56 45 44 47 41 44 45 4e } //1 HOVEDGADEN
		$a_81_7 = {53 4c 55 54 41 4b 54 45 52 } //1 SLUTAKTER
		$a_81_8 = {42 61 63 6b 66 69 73 63 68 65 36 } //1 Backfische6
		$a_81_9 = {66 72 65 6d 6d 65 64 62 67 65 72 73 } //1 fremmedbgers
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}