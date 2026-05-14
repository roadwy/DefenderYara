
rule Trojan_BAT_Formbook_BZ_MTB{
	meta:
		description = "Trojan:BAT/Formbook.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 72 c1 45 00 70 28 06 00 00 0a 72 df 45 00 70 20 00 01 00 00 14 14 17 8d 0a 00 00 01 25 16 06 7b 04 00 00 04 06 7b 05 00 00 04 28 07 00 00 0a a2 6f 08 00 00 0a 74 01 00 00 1b 0b 28 09 00 00 0a 72 01 46 00 70 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}