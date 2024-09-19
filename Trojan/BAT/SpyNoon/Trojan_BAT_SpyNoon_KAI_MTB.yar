
rule Trojan_BAT_SpyNoon_KAI_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.KAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 16 5d 91 13 ?? 07 11 ?? 91 11 ?? 61 13 ?? 11 ?? 17 58 07 8e 69 5d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}