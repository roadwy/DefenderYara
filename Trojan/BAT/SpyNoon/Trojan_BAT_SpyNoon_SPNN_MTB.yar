
rule Trojan_BAT_SpyNoon_SPNN_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.SPNN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 0d 00 73 ?? ?? ?? 0a 13 04 09 11 04 6f ?? ?? ?? 0a 00 11 04 6f ?? ?? ?? 0a 0a de 2b } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}