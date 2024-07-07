
rule Trojan_BAT_SpyNoon_GPA_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 58 09 5d 13 90 01 01 11 90 01 01 02 11 90 01 05 0a 11 09 61 d1 90 01 04 0a 26 00 11 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}