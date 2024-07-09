
rule Trojan_BAT_LummaCStealer_AAKA_MTB{
	meta:
		description = "Trojan:BAT/LummaCStealer.AAKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 05 07 28 ?? 00 00 06 00 11 05 17 28 ?? 00 00 06 00 11 05 09 28 ?? 00 00 06 00 00 11 05 6f ?? 00 00 0a 13 06 11 06 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 07 11 07 0a } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}