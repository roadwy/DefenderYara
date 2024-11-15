
rule Trojan_BAT_DarkTortilla_ZNAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ZNAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 05 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 6f ?? 00 00 0a 13 06 11 06 02 74 ?? 00 00 1b 16 02 14 72 85 24 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 0b 07 74 ?? 00 00 1b 28 ?? 00 00 06 14 72 93 24 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 74 ?? 00 00 1b 0a } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}