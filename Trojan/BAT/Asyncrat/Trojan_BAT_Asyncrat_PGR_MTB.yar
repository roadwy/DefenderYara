
rule Trojan_BAT_Asyncrat_PGR_MTB{
	meta:
		description = "Trojan:BAT/Asyncrat.PGR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 37 00 00 70 28 ?? 00 00 0a 0a 72 69 00 00 70 28 ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 08 06 6f ?? 00 00 0a 08 07 6f ?? 00 00 0a 08 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 0d dd 0d 00 00 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}