
rule Trojan_BAT_Formbook_HLUF_MTB{
	meta:
		description = "Trojan:BAT/Formbook.HLUF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 16 f4 00 00 0c 2b 13 00 72 ?? ?? ?? 70 07 08 28 ?? ?? ?? 06 0b 00 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d e2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}