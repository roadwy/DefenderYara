
rule Trojan_BAT_Asyncrat_PGA_MTB{
	meta:
		description = "Trojan:BAT/Asyncrat.PGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 11 06 11 05 6f ?? 00 00 0a 13 07 09 11 04 20 ff 00 00 00 12 07 28 ?? 00 00 0a 59 1f 72 61 d2 9c 11 06 17 58 13 06 11 04 17 58 13 04 11 06 07 3c 0a 00 00 00 11 04 09 8e 69 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}