
rule Trojan_BAT_Seraph_UIAA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.UIAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 20 ?? 77 00 00 28 ?? 01 00 06 28 ?? 00 00 0a 20 ?? 77 00 00 28 ?? 01 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 09 08 17 73 ?? 00 00 0a 13 04 11 04 06 16 06 8e 69 6f ?? 00 00 0a 09 6f ?? 00 00 0a 0a de 0c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}