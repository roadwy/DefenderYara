
rule Trojan_AndroidOS_Fakecalls_P{
	meta:
		description = "Trojan:AndroidOS/Fakecalls.P,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 78 78 78 78 } //1 http://xxxx
		$a_01_1 = {69 50 78 75 66 78 6c 64 62 69 } //1 iPxufxldbi
		$a_01_2 = {6e 6f 6b 6f 65 6e 72 75 6c } //1 nokoenrul
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}