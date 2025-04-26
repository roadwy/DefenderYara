
rule Trojan_BAT_LummaC_ARIA_MTB{
	meta:
		description = "Trojan:BAT/LummaC.ARIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {38 a3 00 00 00 2b 3c 72 ?? 00 00 70 2b 38 2b 3d 2b 42 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 1a 2c 1d 08 6f ?? 00 00 0a 0d 28 ?? 00 00 0a 09 07 16 07 8e 69 6f ?? 00 00 0a 6f ?? 00 00 0a 0a de 1e } //4
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}