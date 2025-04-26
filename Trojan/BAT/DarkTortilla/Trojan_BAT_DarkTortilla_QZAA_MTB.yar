
rule Trojan_BAT_DarkTortilla_QZAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.QZAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 13 05 00 73 ?? 00 00 0a 13 06 00 11 06 11 05 17 73 ?? 00 00 0a 13 07 11 07 02 74 ?? 00 00 1b 16 02 14 72 ?? ?? 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 07 6f ?? 00 00 0a 00 de 0e } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}