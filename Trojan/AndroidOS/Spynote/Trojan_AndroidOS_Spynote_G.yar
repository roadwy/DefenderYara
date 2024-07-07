
rule Trojan_AndroidOS_Spynote_G{
	meta:
		description = "Trojan:AndroidOS/Spynote.G,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 66 74 65 72 69 6e 73 74 61 6c 6c 6f 70 74 69 6f 6e } //2 Afterinstalloption
		$a_01_1 = {53 43 52 41 63 74 69 76 69 74 79 } //2 SCRActivity
		$a_01_2 = {73 69 6e 67 69 6d 61 6c 6c 69 73 74 65 6e } //2 singimallisten
		$a_01_3 = {72 65 76 6f 63 65 72 63 6c 69 63 6b } //2 revocerclick
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}