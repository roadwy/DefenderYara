
rule Trojan_BAT_Lazy_TVN_MTB{
	meta:
		description = "Trojan:BAT/Lazy.TVN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 02 02 7b ?? 00 00 04 7d ?? 00 00 04 7e ?? 00 00 0a 72 ?? ?? ?? ?? 6f ?? 00 00 0a 0b 07 2c ?? 07 6f ?? 00 00 0a 02 7b ?? 00 00 04 28 ?? 00 00 2b 2c ?? 02 17 7d ?? 00 00 04 de } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}