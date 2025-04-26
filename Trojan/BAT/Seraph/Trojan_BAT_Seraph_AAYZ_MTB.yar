
rule Trojan_BAT_Seraph_AAYZ_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAYZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {6f 06 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 08 07 17 73 ?? 00 00 0a 0d 14 13 04 2b 3c 73 ?? 00 00 0a 13 05 11 05 20 72 8f 00 00 28 ?? 00 00 06 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 de 0c 11 05 2c 07 11 05 6f ?? 00 00 0a dc 11 04 2c c0 09 11 04 16 11 04 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 13 06 de 1e } //3
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}