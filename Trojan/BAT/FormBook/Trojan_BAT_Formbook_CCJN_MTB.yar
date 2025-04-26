
rule Trojan_BAT_Formbook_CCJN_MTB{
	meta:
		description = "Trojan:BAT/Formbook.CCJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 16 05 a2 28 ?? 00 00 0a 26 06 72 ?? ?? ?? ?? 18 18 8d ?? ?? ?? ?? 25 16 04 a2 25 17 05 a2 28 ?? 00 00 0a 0b 03 73 ?? ?? ?? ?? 0c 08 07 74 ?? 00 00 01 16 73 ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 00 09 11 04 6f ?? 00 00 0a 00 11 04 6f ?? 00 00 0a 13 05 de 23 11 04 2c 08 11 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}