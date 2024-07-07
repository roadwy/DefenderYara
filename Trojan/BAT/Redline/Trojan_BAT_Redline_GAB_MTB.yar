
rule Trojan_BAT_Redline_GAB_MTB{
	meta:
		description = "Trojan:BAT/Redline.GAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 07 1d 2d 49 26 26 26 7e 90 01 04 06 18 28 90 01 03 06 7e 90 01 04 06 28 90 01 04 0d 7e 90 01 04 09 02 16 02 8e 69 28 90 01 03 06 2a 0a 38 90 01 04 0b 38 90 01 04 0c 2b 92 28 90 01 03 06 2b 9f 90 00 } //10
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}