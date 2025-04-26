
rule Trojan_BAT_DarkTortilla_APBA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.APBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 00 09 07 1f 10 28 ?? 00 00 2b 28 ?? 00 00 2b 6f ?? 00 00 0a 00 09 19 6f ?? 00 00 0a 00 00 73 ?? 00 00 0a 13 04 09 6f ?? 00 00 0a 13 05 11 05 02 16 02 8e 69 6f ?? 00 00 0a 0c 11 04 08 16 08 8e 69 6f ?? 00 00 0a 00 de 0e } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}