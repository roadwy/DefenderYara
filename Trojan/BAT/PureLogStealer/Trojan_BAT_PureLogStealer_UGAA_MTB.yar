
rule Trojan_BAT_PureLogStealer_UGAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.UGAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 09 08 17 73 ?? 00 00 0a 13 04 28 ?? 00 00 06 16 2c 2d 26 11 04 11 05 28 ?? 00 00 2b 16 11 05 28 ?? 00 00 2b 8e 69 16 2c 1a 26 26 26 26 16 2d da 09 6f ?? 00 00 0a 17 2d 11 26 16 2d f0 de 34 13 05 2b d0 6f ?? 00 00 0a 2b e3 0a 2b ed } //3
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}