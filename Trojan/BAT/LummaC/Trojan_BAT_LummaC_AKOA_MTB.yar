
rule Trojan_BAT_LummaC_AKOA_MTB{
	meta:
		description = "Trojan:BAT/LummaC.AKOA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {17 2c 06 14 38 bb 00 00 00 72 ?? ?? 00 70 38 b7 00 00 00 38 bc 00 00 00 72 ?? ?? 00 70 38 b8 00 00 00 38 bd 00 00 00 38 be 00 00 00 1d 3a c2 00 00 00 26 2b 70 38 71 00 00 00 08 6f ?? ?? 00 0a 13 04 73 ?? ?? 00 0a 13 05 11 05 11 04 17 73 ?? ?? 00 0a 13 06 16 2d 11 2b 0f 19 2c 1e 00 28 ?? 00 00 06 0a de 03 26 de 00 19 2c 0f 06 2c eb 11 06 06 16 06 8e 69 6f ?? ?? 00 0a 11 05 6f ?? ?? 00 0a 0a de 1b } //3
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}