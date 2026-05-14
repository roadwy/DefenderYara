
rule Trojan_BAT_SpyNoon_ZTV_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.ZTV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 07 1f 0a 13 10 38 ?? fe ff ff 11 06 75 ?? 00 00 1b 11 07 8f ?? 00 00 01 25 71 ?? 00 00 01 11 07 03 58 0e 05 59 20 ff 00 00 00 5f d2 61 d2 81 ?? 00 00 01 11 11 20 eb 00 00 00 91 13 10 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}