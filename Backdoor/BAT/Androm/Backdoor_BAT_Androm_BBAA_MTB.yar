
rule Backdoor_BAT_Androm_BBAA_MTB{
	meta:
		description = "Backdoor:BAT/Androm.BBAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 12 01 1f 20 28 ?? 00 00 2b 00 06 07 6f ?? 00 00 0a 00 06 1f 10 8d ?? 00 00 01 6f ?? 00 00 0a 00 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 02 19 73 ?? 00 00 0a 0d 03 18 73 ?? 00 00 0a 13 04 09 08 16 73 ?? 00 00 0a 13 05 00 11 05 11 04 6f ?? 00 00 0a 00 00 de 0d } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}