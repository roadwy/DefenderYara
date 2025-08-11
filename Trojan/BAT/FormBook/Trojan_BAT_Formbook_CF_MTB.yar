
rule Trojan_BAT_Formbook_CF_MTB{
	meta:
		description = "Trojan:BAT/Formbook.CF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {5f 13 0b 02 11 0a 11 0b 6f ?? 01 00 0a 13 0c 12 0c 28 ?? 01 00 0a 16 61 d2 13 0d 12 0c 28 ?? 01 00 0a 16 61 d2 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}