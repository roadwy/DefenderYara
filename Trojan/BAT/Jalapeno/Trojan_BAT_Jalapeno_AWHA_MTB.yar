
rule Trojan_BAT_Jalapeno_AWHA_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.AWHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 00 08 07 6f ?? 00 00 0a 16 73 ?? 00 00 0a 0d 00 14 13 04 02 8e 69 17 58 8d ?? 00 00 01 13 04 16 13 05 09 11 04 16 02 8e 69 6f ?? 00 00 0a 13 05 11 05 17 58 8d ?? 00 00 01 0a 11 04 06 11 05 28 ?? 00 00 0a 00 09 6f ?? 00 00 0a 00 00 de 12 } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}