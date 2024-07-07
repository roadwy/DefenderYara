
rule Trojan_BAT_RedlineStealer_NA_MTB{
	meta:
		description = "Trojan:BAT/RedlineStealer.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 08 91 0d 08 1f 09 5d 90 01 02 03 11 04 9a 13 05 02 08 11 05 09 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}