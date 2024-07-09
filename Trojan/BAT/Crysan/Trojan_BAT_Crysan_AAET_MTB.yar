
rule Trojan_BAT_Crysan_AAET_MTB{
	meta:
		description = "Trojan:BAT/Crysan.AAET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 06 07 16 1a 6f ?? 00 00 0a 26 07 16 28 ?? 00 00 0a 0c 06 16 73 ?? 00 00 0a 0d 08 8d ?? 00 00 01 13 04 09 11 04 16 08 6f ?? 00 00 0a 26 11 04 28 ?? 00 00 2b 28 ?? 00 00 2b 13 05 de 14 09 2c 06 09 6f ?? 00 00 0a dc } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}