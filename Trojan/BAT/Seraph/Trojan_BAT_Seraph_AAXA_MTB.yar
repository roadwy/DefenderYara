
rule Trojan_BAT_Seraph_AAXA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 02 11 03 11 01 11 03 91 11 04 59 d2 9c 20 01 00 00 00 7e ?? 02 00 04 7b ?? 02 00 04 3a ?? fe ff ff 26 20 02 00 00 00 38 ?? fe ff ff 72 2f 00 00 70 28 ?? 00 00 0a 13 04 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}