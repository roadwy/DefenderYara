
rule Trojan_BAT_Seraph_AAGX_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAGX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 20 00 01 00 00 6f ?? 00 00 0a 06 20 b1 68 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 20 0c 68 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 08 07 17 73 ?? 00 00 0a 0d 28 ?? 00 00 06 13 04 09 11 04 16 11 04 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 13 05 de 1e 09 2c 06 09 6f ?? 00 00 0a dc } //3
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}