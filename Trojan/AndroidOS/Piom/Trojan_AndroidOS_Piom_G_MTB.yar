
rule Trojan_AndroidOS_Piom_G_MTB{
	meta:
		description = "Trojan:AndroidOS/Piom.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 72 74 49 6d 61 67 65 } //1 StartImage
		$a_01_1 = {74 6f 4c 6f 67 69 6e 41 63 74 69 76 69 74 79 } //1 toLoginActivity
		$a_01_2 = {75 70 6c 6f 61 64 46 69 6c 65 } //1 uploadFile
		$a_01_3 = {43 4f 55 4e 54 5f 43 4c 49 43 4b } //1 COUNT_CLICK
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}