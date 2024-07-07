
rule Trojan_BAT_Redline_GTD_MTB{
	meta:
		description = "Trojan:BAT/Redline.GTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {02 1a 58 11 04 16 08 28 90 01 03 0a 28 90 01 03 0a 11 04 16 11 04 8e 69 6f 90 01 03 0a 13 05 7e 90 01 04 11 05 6f 90 01 03 0a 7e 90 01 04 02 6f 90 01 03 0a 7e 90 01 04 6f 90 01 03 0a 17 59 28 90 01 03 0a 16 7e 90 01 04 02 1a 28 90 01 03 0a 11 05 0d 90 00 } //10
		$a_80_1 = {49 6f 73 44 6f 78 65 64 6d 66 6a 72 69 74 46 61 73 6d } //IosDoxedmfjritFasm  1
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}