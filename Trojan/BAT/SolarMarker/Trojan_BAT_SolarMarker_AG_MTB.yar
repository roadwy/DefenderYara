
rule Trojan_BAT_SolarMarker_AG_MTB{
	meta:
		description = "Trojan:BAT/SolarMarker.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 04 2b 17 09 11 04 08 17 20 ?? 00 00 00 6f ?? 00 00 0a d2 9c 11 04 17 58 13 04 11 04 09 8e 69 17 59 fe 04 13 10 11 10 2d da } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}