
rule Trojan_BAT_zgRAT_NA_MTB{
	meta:
		description = "Trojan:BAT/zgRAT.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {61 19 11 1b 58 61 11 ?? 61 d2 9c 20 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}