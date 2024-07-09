
rule Trojan_BAT_Seraph_FAG_MTB{
	meta:
		description = "Trojan:BAT/Seraph.FAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 01 18 5b 8d ?? 00 00 01 13 02 38 ?? ff ff ff 11 00 28 ?? 00 00 06 13 01 38 ?? ff ff ff 11 02 11 03 18 5b 11 00 11 03 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 06 9c 20 03 00 00 00 38 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}