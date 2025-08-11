
rule Trojan_BAT_DarkTortilla_AUVA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AUVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 14 0c 14 0d 14 13 04 14 13 05 00 28 ?? ?? 00 0a 0d 09 14 fe 03 13 06 11 06 2c 27 09 07 6f ?? ?? 00 0a 00 09 07 6f ?? ?? 00 0a 00 09 6f ?? ?? 00 0a 13 07 11 07 02 16 02 8e 69 6f ?? ?? 00 0a 0a de 41 00 de 39 00 09 14 fe 03 13 08 11 08 2c 07 } //5
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}