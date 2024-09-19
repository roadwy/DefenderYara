
rule Trojan_BAT_Formbook_AMAI_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AMAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 02 16 03 8e 69 6f ?? 00 00 0a 0b 07 28 ?? 00 00 0a 0c 08 6f ?? 00 00 0a 0d 09 16 9a 13 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}