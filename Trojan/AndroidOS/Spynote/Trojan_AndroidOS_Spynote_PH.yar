
rule Trojan_AndroidOS_Spynote_PH{
	meta:
		description = "Trojan:AndroidOS/Spynote.PH,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {4d 54 55 30 4c 6a 49 78 4e 43 34 7a 4d 69 34 7a } //1 MTU0LjIxNC4zMi4z
		$a_01_1 = {47 72 61 62 20 41 6e 64 20 47 4f 20 76 } //1 Grab And GO v
		$a_01_2 = {61 70 70 2e 68 6f 6d 65 2d 61 61 61 2e 69 63 75 2f } //1 app.home-aaa.icu/
		$a_01_3 = {4d 6a 41 79 4c 6a 67 33 4c 6a 49 79 4d 53 34 79 4d 7a 63 } //1 MjAyLjg3LjIyMS4yMzc
		$a_01_4 = {47 72 61 62 20 6e 20 47 6f 20 76 } //1 Grab n Go v
		$a_01_5 = {70 6c 75 73 2e 65 6c 65 63 74 65 64 2e 63 6f 73 74 6d } //1 plus.elected.costm
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}