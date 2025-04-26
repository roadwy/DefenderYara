
rule Trojan_BAT_DarkTortilla_WGAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.WGAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 02 74 15 00 00 01 06 28 ?? 00 00 0a 28 ?? 00 00 06 0b 07 74 ?? 00 00 1b 28 ?? 01 00 06 74 ?? 00 00 1b 0c 08 28 ?? 00 00 06 0d 09 28 ?? 00 00 0a 28 ?? 00 00 06 74 ?? 00 00 01 13 04 11 04 6f ?? 00 00 0a 13 05 11 05 fe 0b 00 00 02 74 ?? 00 00 1b 28 ?? 01 00 06 26 de 10 } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}