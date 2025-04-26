
rule Trojan_BAT_SpyNoon_GPA_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 58 09 5d 13 ?? 11 ?? 02 11 ?? ?? ?? ?? ?? 0a 11 09 61 d1 ?? ?? ?? ?? 0a 26 00 11 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}