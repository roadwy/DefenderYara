
rule Trojan_BAT_SpyNoon_ABP_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.ABP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 03 11 04 6f ?? 00 00 0a 13 06 38 88 00 00 00 11 01 73 ?? 00 00 06 13 02 20 03 00 00 00 7e ?? 01 00 04 7b ?? 01 00 04 3a c1 fc ff ff 26 20 03 00 00 00 38 b6 fc ff ff 03 72 5d 0e 00 70 28 94 00 00 0a 3a d1 00 00 00 38 6f fe ff ff 11 0b 6f ?? 00 00 0a 2a 11 08 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}