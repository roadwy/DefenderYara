
rule Trojan_BAT_NjRAT_KAE_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 08 09 9a 13 04 11 04 28 ?? 00 00 0a 23 00 00 00 00 00 ?? ?? ?? 59 28 ?? 00 00 0a b7 13 05 06 11 05 28 ?? 00 00 0a 6f ?? 00 00 0a 26 00 09 17 d6 0d 09 08 8e 69 fe 04 13 06 11 06 2d c2 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}