
rule Trojan_BAT_Heracles_ABQR_MTB{
	meta:
		description = "Trojan:BAT/Heracles.ABQR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 00 06 18 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 0b 7e ?? 00 00 04 02 07 6f ?? 00 00 06 0c 2b 00 08 2a 90 0a 3f 00 28 ?? 00 00 0a 0a 06 7e ?? 00 00 04 28 ?? 00 00 0a 6f } //5
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}