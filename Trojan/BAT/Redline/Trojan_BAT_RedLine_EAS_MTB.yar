
rule Trojan_BAT_RedLine_EAS_MTB{
	meta:
		description = "Trojan:BAT/RedLine.EAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 03 13 07 38 ?? 00 00 00 11 03 11 08 18 5b 11 01 11 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 20 00 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 39 ?? ff ff ff 26 20 00 00 00 00 38 ?? ff ff ff 16 13 08 38 ?? ff ff ff 11 08 18 58 13 08 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}