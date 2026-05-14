
rule Trojan_BAT_PureRat_AB_MTB{
	meta:
		description = "Trojan:BAT/PureRat.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {38 a6 ff ff ff 00 11 11 11 00 6f ?? 00 00 0a 17 73 0b 00 00 0a 13 02 38 00 00 00 00 00 11 02 02 16 02 8e 69 6f ?? 00 00 0a 38 2e 00 00 00 38 09 00 00 00 20 00 00 00 00 fe 0e 0e 00 fe 0c 0e 00 45 01 00 00 00 4c 00 00 00 fe 0c 0e 00 20 dc 03 00 00 3b e5 ff ff ff 38 39 00 00 00 11 02 6f ?? 00 00 0a 38 00 00 00 00 11 11 6f ?? 00 00 0a 73 0f 00 00 0a 13 03 20 04 00 00 00 7e 4d 00 00 04 7b 47 00 00 04 3a b6 ff ff ff 26 20 } //6
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //2 FromBase64String
		$a_01_2 = {54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //2 TripleDESCryptoServiceProvider
		$a_01_3 = {47 5a 69 70 53 74 72 65 61 6d } //2 GZipStream
	condition:
		((#a_03_0  & 1)*6+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=12
 
}