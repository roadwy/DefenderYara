
rule Trojan_BAT_Wagex_BZAA_MTB{
	meta:
		description = "Trojan:BAT/Wagex.BZAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 07 11 06 91 6f 90 01 01 00 00 0a 00 00 11 06 25 17 59 13 06 16 fe 02 13 07 11 07 2d e3 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}