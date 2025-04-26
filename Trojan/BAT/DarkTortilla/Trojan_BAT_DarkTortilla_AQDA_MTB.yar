
rule Trojan_BAT_DarkTortilla_AQDA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AQDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 05 75 6a 00 00 01 02 74 0b 00 00 1b 16 02 14 1e d0 03 00 00 02 28 ?? 00 00 0a 20 a7 8c 9d 3e 28 ?? 02 00 06 16 8d 06 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 13 06 17 13 0e 2b 9d } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}