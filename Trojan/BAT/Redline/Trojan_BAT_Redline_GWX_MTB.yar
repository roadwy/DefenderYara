
rule Trojan_BAT_Redline_GWX_MTB{
	meta:
		description = "Trojan:BAT/Redline.GWX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {13 06 11 06 08 6f 90 01 03 0a 11 06 18 6f 90 01 03 0a 11 06 18 6f 90 01 03 0a 11 06 0d 2b 22 2b 23 2b 28 2b 2a 06 16 06 8e 69 6f 90 01 03 0a 13 05 28 90 01 03 0a 11 05 6f 90 01 03 0a 13 07 de 26 09 2b db 6f 90 01 03 0a 2b d6 13 04 2b d4 11 04 2b d2 90 00 } //10
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}