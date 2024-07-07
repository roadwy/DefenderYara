
rule Trojan_BAT_Crysan_ABRE_MTB{
	meta:
		description = "Trojan:BAT/Crysan.ABRE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 13 01 38 90 01 03 00 dd 90 01 03 ff 26 90 0a 2f 00 28 90 01 03 06 13 00 38 90 01 03 00 28 90 01 03 06 11 00 6f 90 01 03 0a 28 90 01 03 0a 28 90 00 } //3
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 41 00 70 00 70 00 31 00 34 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 WindowsFormsApp14.Properties.Resources
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}