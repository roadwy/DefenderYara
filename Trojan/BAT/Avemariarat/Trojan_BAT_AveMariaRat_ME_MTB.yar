
rule Trojan_BAT_AveMariaRat_ME_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRat.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {2d 00 65 00 6e 00 63 00 20 00 61 00 51 00 42 00 77 00 41 00 47 00 4d 00 41 00 62 00 77 00 42 00 75 00 } //1 -enc aQBwAGMAbwBu
		$a_01_1 = {70 72 6f 78 79 } //1 proxy
		$a_01_2 = {54 6f 53 74 72 69 6e 67 } //1 ToString
		$a_01_3 = {42 61 73 65 36 34 45 6e 63 6f 64 65 72 } //1 Base64Encoder
		$a_01_4 = {48 69 64 64 65 6e } //1 Hidden
		$a_01_5 = {67 65 74 5f 4b 65 79 } //1 get_Key
		$a_01_6 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_7 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_8 = {43 6f 64 65 41 63 63 65 73 73 50 65 72 6d 69 73 73 69 6f 6e } //1 CodeAccessPermission
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}