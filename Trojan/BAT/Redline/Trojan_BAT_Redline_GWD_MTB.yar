
rule Trojan_BAT_Redline_GWD_MTB{
	meta:
		description = "Trojan:BAT/Redline.GWD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {04 13 04 28 90 01 03 0a 11 04 6f 90 01 03 0a 13 05 09 11 05 6f 90 01 03 0a 00 09 6f 90 01 03 0a 13 06 11 06 06 16 06 8e 69 6f 90 01 03 0a 13 07 28 90 01 03 0a 11 07 6f 90 01 03 0a 13 08 11 08 13 09 de 16 90 00 } //10
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {44 73 78 7a 61 73 } //1 Dsxzas
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}