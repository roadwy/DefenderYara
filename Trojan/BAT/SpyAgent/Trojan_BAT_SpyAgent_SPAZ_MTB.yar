
rule Trojan_BAT_SpyAgent_SPAZ_MTB{
	meta:
		description = "Trojan:BAT/SpyAgent.SPAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 06 09 06 9a 1f 10 28 ?? ?? ?? 0a 9c 06 17 58 0a 06 09 8e 69 fe 04 13 0b 11 0b 2d e2 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}