
rule Trojan_AndroidOS_SAgnt_AI_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.AI!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {77 69 66 69 56 6f 69 64 } //1 wifiVoid
		$a_01_1 = {41 72 61 62 57 61 72 65 } //1 ArabWare
		$a_01_2 = {5f 53 6d 53 } //1 _SmS
		$a_01_3 = {77 69 70 65 44 61 74 61 } //1 wipeData
		$a_01_4 = {68 69 64 65 4b 65 79 62 6f 61 72 64 } //1 hideKeyboard
		$a_01_5 = {63 6f 6d 2f 73 61 69 64 2f 63 6f 6d } //1 com/said/com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}