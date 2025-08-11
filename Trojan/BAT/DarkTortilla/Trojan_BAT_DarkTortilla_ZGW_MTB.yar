
rule Trojan_BAT_DarkTortilla_ZGW_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ZGW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 00 09 09 6f ?? 01 00 0a 09 6f ?? 01 00 0a 6f ?? 01 00 0a 13 04 00 73 ?? 01 00 0a 13 05 00 11 05 11 04 17 73 ?? 01 00 0a 13 07 11 07 02 16 02 8e 69 6f ?? 01 00 0a 00 11 07 6f ?? 01 00 0a 00 de 0e } //6
		$a_03_1 = {03 09 11 05 6f ?? 01 00 0a 13 06 02 11 06 04 28 ?? 00 00 0a 28 ?? 00 00 06 13 07 06 09 11 05 11 07 } //5
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5+(#a_01_2  & 1)*1) >=12
 
}