
rule Trojan_BAT_Formbook_PTEX_MTB{
	meta:
		description = "Trojan:BAT/Formbook.PTEX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 90 00 00 0a 17 73 6b 00 00 0a 25 02 16 02 8e 69 6f 91 00 00 0a 6f 92 00 00 0a 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}