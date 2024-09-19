
rule Trojan_BAT_XWorm_AMAJ_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AMAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 0a 06 72 ?? 00 00 70 6f ?? 00 00 0a 28 ?? 00 00 06 0b 07 06 72 ?? 01 00 70 6f ?? 00 00 0a 28 ?? 00 00 06 0c 02 28 ?? 00 00 06 0d 08 09 8e 69 1f 40 12 04 28 ?? 00 00 06 26 09 16 08 09 8e 69 28 ?? 00 00 0a 00 08 09 8e 69 11 04 12 05 28 ?? 00 00 06 26 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}