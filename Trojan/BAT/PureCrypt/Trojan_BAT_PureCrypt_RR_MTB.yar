
rule Trojan_BAT_PureCrypt_RR_MTB{
	meta:
		description = "Trojan:BAT/PureCrypt.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {11 04 28 01 00 00 2b 28 02 00 00 2b 13 05 38 12 00 00 00 11 03 11 04 16 11 02 6f 17 00 00 0a 26 38 db ff ff ff } //10
		$a_01_1 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_01_2 = {42 69 74 43 6f 6e 76 65 72 74 65 72 00 54 6f 49 6e 74 33 32 } //1 楂䍴湯敶瑲牥吀䥯瑮㈳
		$a_01_3 = {54 72 69 6d } //1 Trim
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}