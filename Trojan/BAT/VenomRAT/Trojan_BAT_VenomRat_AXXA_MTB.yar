
rule Trojan_BAT_VenomRat_AXXA_MTB{
	meta:
		description = "Trojan:BAT/VenomRat.AXXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 29 02 14 72 ?? ?? 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 0d 07 09 b4 6f ?? 00 00 0a 00 08 17 d6 0c 00 08 8c ?? 00 00 01 02 14 72 ?? ?? 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 16 28 ?? 00 00 0a 13 04 11 04 2d b0 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}