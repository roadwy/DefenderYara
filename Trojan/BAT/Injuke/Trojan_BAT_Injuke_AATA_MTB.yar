
rule Trojan_BAT_Injuke_AATA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AATA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 3a 08 13 04 16 13 05 11 04 12 05 28 ?? 00 00 0a 07 09 18 6f ?? 00 00 0a 06 28 ?? 00 00 0a 13 06 08 09 11 06 6f ?? 00 00 0a de 0c 11 05 2c 07 11 04 28 ?? 00 00 0a dc } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}