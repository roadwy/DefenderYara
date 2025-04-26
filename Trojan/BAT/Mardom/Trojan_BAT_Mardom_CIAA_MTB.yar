
rule Trojan_BAT_Mardom_CIAA_MTB{
	meta:
		description = "Trojan:BAT/Mardom.CIAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 07 28 ?? 00 00 0a 91 8c ?? 00 00 01 09 07 09 8e b7 8c ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 91 8c ?? 00 00 01 07 04 8c ?? 00 00 01 28 ?? 00 00 0a 09 8e b7 8c ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 11 04 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 9c 07 11 07 12 01 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}