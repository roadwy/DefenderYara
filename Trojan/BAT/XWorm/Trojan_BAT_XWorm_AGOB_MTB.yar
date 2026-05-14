
rule Trojan_BAT_XWorm_AGOB_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AGOB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 13 09 11 09 28 ?? 00 00 0a 72 ?? ?? 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 00 11 09 28 ?? 00 00 0a 72 ?? ?? 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 00 11 09 11 09 6f ?? 00 00 0a 11 09 6f ?? 00 00 0a 6f ?? 00 00 0a 13 0a 02 03 9a 28 ?? 00 00 0a 13 0b 11 0b 73 ?? 00 00 0a 13 0c 11 0c 11 0a 16 73 ?? 00 00 0a 13 0d 11 0d 73 ?? 00 00 0a 13 0e 00 11 0e 6f ?? 00 00 0a 0a 00 de 0d } //5
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}