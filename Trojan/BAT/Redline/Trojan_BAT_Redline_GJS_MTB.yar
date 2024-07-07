
rule Trojan_BAT_Redline_GJS_MTB{
	meta:
		description = "Trojan:BAT/Redline.GJS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 90 01 03 06 03 08 17 58 03 8e 69 5d 91 59 20 90 01 04 58 17 58 20 90 01 04 5d d2 9c 08 17 58 0c 08 6a 03 8e 69 17 59 6a 06 17 58 6e 5a 31 ac 0f 01 03 8e 69 17 59 28 90 01 03 2b 03 2a 90 00 } //10
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {66 66 63 68 6b 66 66 61 66 66 73 64 73 73 66 6a } //1 ffchkffaffsdssfj
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}