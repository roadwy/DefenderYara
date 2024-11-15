
rule Trojan_BAT_Formbook_RDAX_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 02 6f 18 00 00 0a 16 02 6f 1a 00 00 0a 6f 1b 00 00 0a 28 05 00 00 2b 0c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}