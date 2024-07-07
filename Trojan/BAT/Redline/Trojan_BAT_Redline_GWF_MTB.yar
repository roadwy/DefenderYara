
rule Trojan_BAT_Redline_GWF_MTB{
	meta:
		description = "Trojan:BAT/Redline.GWF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {03 28 1d 00 00 0a 0a 28 90 01 03 0a 04 6f 90 01 03 0a 0b 28 90 01 03 0a 07 6f 90 01 03 0a 0b 06 07 28 90 01 03 06 0c 03 08 28 90 01 03 0a 00 03 03 7e 18 00 00 04 28 90 00 } //10
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {41 45 53 5f 45 6e 63 72 79 70 74 } //1 AES_Encrypt
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}