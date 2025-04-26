
rule Trojan_BAT_XWorm_AZEA_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AZEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b 69 38 6e 00 00 00 2b 31 72 ?? 05 00 70 2b 2d 2b 32 2b 37 72 ?? 06 00 70 2b 33 2b 38 2b 3d 6f ?? 00 00 0a 28 ?? ?? 00 06 0b 07 16 07 8e 69 6f ?? 00 00 0a 0c 1e 2c cf de 2f 06 2b cc 28 ?? 00 00 0a 2b cc 6f ?? 00 00 0a 2b c7 06 2b c6 28 ?? 00 00 0a 2b c6 6f ?? 00 00 0a 2b c1 06 2b c0 } //3
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}