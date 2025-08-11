
rule Trojan_BAT_DarkTortilla_ANWA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ANWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 13 05 11 05 11 04 1f 20 6f ?? 01 00 0a 6f ?? 01 00 0a 00 11 05 11 04 1f 10 6f ?? 01 00 0a 6f ?? 01 00 0a 00 11 05 11 05 6f ?? 01 00 0a 11 05 6f ?? 01 00 0a 6f ?? 01 00 0a 13 06 00 73 ?? 00 00 0a 13 07 00 11 07 11 06 17 73 ?? 01 00 0a 13 09 11 09 02 16 02 8e 69 6f ?? 01 00 0a 00 11 09 6f ?? 01 00 0a 00 de 0e } //5
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}