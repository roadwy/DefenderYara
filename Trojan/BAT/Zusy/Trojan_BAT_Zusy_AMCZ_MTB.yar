
rule Trojan_BAT_Zusy_AMCZ_MTB{
	meta:
		description = "Trojan:BAT/Zusy.AMCZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 00 07 28 ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 06 08 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 0d 09 04 16 05 8e 69 6f ?? 00 00 0a 13 04 de 16 } //4
		$a_80_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //CreateDecryptor  1
	condition:
		((#a_03_0  & 1)*4+(#a_80_1  & 1)*1) >=5
 
}