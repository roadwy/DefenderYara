
rule Trojan_BAT_Formbook_QBFA_MTB{
	meta:
		description = "Trojan:BAT/Formbook.QBFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 16 44 00 00 0c 2b 13 00 72 ?? ?? ?? 70 07 08 28 ?? ?? ?? 06 0b 00 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d e2 } //1
		$a_01_1 = {56 00 6f 00 72 00 6f 00 6e 00 69 00 } //1 Voroni
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}