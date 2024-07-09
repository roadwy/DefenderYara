
rule Trojan_BAT_SpyLoader_NL_MTB{
	meta:
		description = "Trojan:BAT/SpyLoader.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 16 00 00 0a 28 ?? 00 00 06 6f ?? 00 00 0a 0a 16 0b 2b 13 02 07 06 07 06 8e 69 5d 91 02 07 91 61 d2 9c 07 17 58 0b 07 02 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}