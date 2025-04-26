
rule Trojan_BAT_Heracles_AAAZ_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AAAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 11 04 6f ?? 00 00 0a 02 11 05 6f ?? 00 00 0a fe 01 16 fe 01 13 07 11 07 2d 1d 00 06 02 11 05 07 58 6f ?? 00 00 0a 13 08 12 08 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 2b 17 00 11 05 17 58 13 05 11 05 02 6f ?? 00 00 0a fe 04 13 07 11 07 2d b0 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}