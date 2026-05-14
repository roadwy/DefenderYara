
rule Trojan_BAT_XWorm_AFOB_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AFOB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {70 0c 06 28 ?? 00 00 0a 0d 07 28 ?? 00 00 0a 13 04 08 28 ?? 00 00 0a 13 05 73 ?? 00 00 0a 13 07 11 07 11 04 6f ?? 00 00 0a 11 07 11 05 6f ?? 00 00 0a 11 07 17 6f ?? 00 00 0a 11 07 18 6f ?? 00 00 0a 73 ?? 00 00 0a 13 08 11 08 11 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 09 11 09 09 16 09 8e 69 6f ?? 00 00 0a 11 09 6f ?? 00 00 0a 11 08 6f ?? 00 00 0a 13 06 de 0c } //5
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}