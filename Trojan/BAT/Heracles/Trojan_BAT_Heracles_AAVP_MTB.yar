
rule Trojan_BAT_Heracles_AAVP_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AAVP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 0c 16 0d 2b 4e 08 09 6f ?? 00 00 0a 28 ?? 00 00 0a 13 04 11 04 28 ?? 00 00 0a 20 c8 00 00 00 da 20 96 00 00 00 da 20 9b 00 00 00 da 1f 78 da 20 c8 00 00 00 da 13 05 11 05 28 ?? 00 00 0a 28 ?? 00 00 0a 13 06 07 11 06 28 ?? 00 00 0a 0b 00 09 17 d6 0d 09 08 6f ?? 00 00 0a fe 04 13 07 11 07 2d a3 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}