
rule Trojan_BAT_Heracles_SPDO_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SPDO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 61 d2 13 ?? 11 ?? 07 11 ?? 17 58 09 5d 91 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}