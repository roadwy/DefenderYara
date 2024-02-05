
rule Trojan_BAT_RedLine_EAS_MTB{
	meta:
		description = "Trojan:BAT/RedLine.EAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 03 13 07 38 90 01 01 00 00 00 11 03 11 08 18 5b 11 01 11 08 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 9c 20 00 00 00 00 7e 90 01 01 00 00 04 7b 90 01 01 00 00 04 39 90 01 01 ff ff ff 26 20 00 00 00 00 38 90 01 01 ff ff ff 16 13 08 38 90 01 01 ff ff ff 11 08 18 58 13 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}