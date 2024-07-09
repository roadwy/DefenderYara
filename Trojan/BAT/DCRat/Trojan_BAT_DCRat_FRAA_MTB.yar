
rule Trojan_BAT_DCRat_FRAA_MTB{
	meta:
		description = "Trojan:BAT/DCRat.FRAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 05 2b 2f 06 07 17 8d ?? 00 00 01 25 16 11 05 8c ?? 00 00 01 03 28 ?? 00 00 0a a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 05 17 d6 13 05 11 05 11 04 31 cb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}