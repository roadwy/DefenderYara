
rule Trojan_BAT_Formbook_PADW_MTB{
	meta:
		description = "Trojan:BAT/Formbook.PADW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 07 02 07 91 04 07 04 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d e1 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}