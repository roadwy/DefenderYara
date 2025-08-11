
rule Trojan_BAT_Formbook_SLER_MTB{
	meta:
		description = "Trojan:BAT/Formbook.SLER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 4f 00 00 06 28 2c 00 00 0a 0b 00 06 28 05 00 00 06 0c 08 39 0a 00 00 00 08 8e 16 fe 03 38 01 00 00 00 16 0d 09 39 0f 00 00 00 00 07 08 28 0a 00 00 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}