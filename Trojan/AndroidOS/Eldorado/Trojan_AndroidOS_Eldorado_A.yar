
rule Trojan_AndroidOS_Eldorado_A{
	meta:
		description = "Trojan:AndroidOS/Eldorado.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 07 00 00 "
		
	strings :
		$a_01_0 = {73 65 74 51 75 69 6e 74 65 73 73 65 6e 74 69 61 6c } //1 setQuintessential
		$a_01_1 = {73 79 6e 63 48 61 72 62 69 6e 67 65 72 } //1 syncHarbinger
		$a_01_2 = {75 73 65 4c 61 6e 67 43 6f 75 6e 74 72 79 48 6c } //1 useLangCountryHl
		$a_01_3 = {75 65 47 71 4f 72 6e 73 43 79 } //1 ueGqOrnsCy
		$a_01_4 = {76 69 65 77 53 75 72 72 65 70 74 69 74 69 6f 75 73 } //1 viewSurreptitious
		$a_01_5 = {73 61 76 65 4d 65 6c 6c 69 66 6c 75 6f 75 73 } //1 saveMellifluous
		$a_01_6 = {76 69 65 77 45 6c 69 73 69 6f 6e } //1 viewElision
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=3
 
}