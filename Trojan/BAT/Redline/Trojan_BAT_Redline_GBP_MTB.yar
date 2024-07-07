
rule Trojan_BAT_Redline_GBP_MTB{
	meta:
		description = "Trojan:BAT/Redline.GBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 0e 11 12 58 11 15 11 15 8e 69 12 02 17 19 6f 90 01 03 06 26 11 0f 1f 28 58 13 0f 11 11 17 58 13 11 11 11 11 10 17 59 3e 70 ff ff ff 90 00 } //10
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}