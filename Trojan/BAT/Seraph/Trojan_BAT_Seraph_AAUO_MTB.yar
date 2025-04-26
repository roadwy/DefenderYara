
rule Trojan_BAT_Seraph_AAUO_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAUO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 01 11 03 16 28 ?? 00 00 06 13 0b 20 02 00 00 00 38 ?? ff ff ff 12 0b 28 ?? 00 00 0a 13 05 20 02 00 00 00 7e ?? 09 00 04 7b ?? 0a 00 04 3a ?? ff ff ff 26 20 06 00 00 00 38 ?? ff ff ff 11 0a 28 ?? 00 00 06 13 09 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}