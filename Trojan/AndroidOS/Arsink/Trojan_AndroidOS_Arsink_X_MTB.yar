
rule Trojan_AndroidOS_Arsink_X_MTB{
	meta:
		description = "Trojan:AndroidOS/Arsink.X!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 76 69 6c 52 61 74 } //1 EvilRat
		$a_01_1 = {44 65 6d 6f 6e 53 65 6e } //1 DemonSen
		$a_01_2 = {54 68 65 45 76 69 6c 20 43 61 6d 65 72 61 } //1 TheEvil Camera
		$a_01_3 = {68 69 64 65 5f 61 70 70 } //1 hide_app
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}