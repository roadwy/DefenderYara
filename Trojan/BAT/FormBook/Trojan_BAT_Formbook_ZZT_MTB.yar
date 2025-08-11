
rule Trojan_BAT_Formbook_ZZT_MTB{
	meta:
		description = "Trojan:BAT/Formbook.ZZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {26 02 11 13 11 14 6f ?? 01 00 0a 13 16 11 0b 11 15 12 16 28 ?? 01 00 0a 6f ?? 01 00 0a 12 16 28 ?? 01 00 0a 13 17 12 16 28 ?? 01 00 0a 13 18 12 16 28 ?? 01 00 0a 13 19 11 17 11 18 58 11 19 58 26 04 03 6f ?? 01 00 0a 59 25 17 28 ?? 01 00 0a 8d db 00 00 01 26 19 28 ?? 01 00 0a 13 1a 11 1a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}