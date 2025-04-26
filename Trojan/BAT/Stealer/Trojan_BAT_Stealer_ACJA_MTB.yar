
rule Trojan_BAT_Stealer_ACJA_MTB{
	meta:
		description = "Trojan:BAT/Stealer.ACJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 06 11 04 6f ?? 00 00 0a 00 00 de 0b 09 2c 07 09 6f ?? 00 00 0a 00 dc 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 0b 07 02 16 02 8e 69 6f ?? 00 00 0a 0c 08 13 05 2b 00 11 05 2a } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}