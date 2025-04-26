
rule Trojan_BAT_MassLogger_AUJA_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.AUJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 28 ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 06 08 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 0e 05 16 0e 05 8e 69 6f ?? 00 00 0a 0d 2b 00 09 2a } //5
		$a_01_1 = {41 6e 74 69 42 6f 73 73 69 6e 67 } //1 AntiBossing
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}