
rule Trojan_BAT_AveMaria_ABYB_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.ABYB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 00 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 02 73 ?? 00 00 0a 0c 08 07 16 73 ?? 00 00 0a 0d 00 02 8e 69 8d ?? 00 00 01 13 04 09 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 05 11 04 11 05 28 ?? 00 00 2b 28 ?? 00 00 2b 13 06 de 2c 09 2c 07 09 6f ?? 00 00 0a 00 dc } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}