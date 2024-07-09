
rule Trojan_BAT_Vidar_AANF_MTB{
	meta:
		description = "Trojan:BAT/Vidar.AANF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 25 11 02 28 ?? 00 00 06 25 17 28 ?? 00 00 06 25 18 28 ?? 00 00 06 25 11 04 6f ?? 00 00 0a 28 ?? 00 00 06 11 01 16 11 01 8e 69 28 ?? 00 00 06 13 03 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}