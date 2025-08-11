
rule Trojan_BAT_Formbook_LLT_MTB{
	meta:
		description = "Trojan:BAT/Formbook.LLT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 72 61 00 00 70 28 0b 00 00 0a 6f 0c 00 00 0a 06 72 93 00 00 70 28 ?? 00 00 0a 6f 0d 00 00 0a 06 6f 0e 00 00 0a 03 16 03 8e 69 6f ?? 00 00 0a 0b dd 0d 00 00 00 06 39 06 00 00 00 06 6f 10 00 00 0a dc 07 2a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}