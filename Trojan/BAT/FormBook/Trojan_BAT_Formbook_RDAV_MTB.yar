
rule Trojan_BAT_Formbook_RDAV_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 6f 48 00 00 0a 28 49 00 00 0a 0c 08 6f 4a 00 00 0a 16 9a 0d } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}