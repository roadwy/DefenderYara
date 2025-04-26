
rule Trojan_BAT_Stealer_ZCAA_MTB{
	meta:
		description = "Trojan:BAT/Stealer.ZCAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 06 17 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 03 04 6f ?? 00 00 0a 0b 07 02 16 02 8e 69 6f ?? 00 00 0a 0c de 14 } //3
		$a_01_1 = {11 07 59 13 08 11 08 8d 2b 00 00 01 13 09 16 13 0d 2b 12 11 09 11 0d 07 11 07 11 0d 58 91 9c 11 0d 17 58 13 0d 11 0d 11 08 32 e8 } //2
		$a_03_2 = {11 0b 2c 0a 11 04 11 0a 6f ?? 00 00 0a 26 11 0a 17 58 13 0a 11 0a 11 05 11 06 59 31 bd } //2
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1) >=8
 
}