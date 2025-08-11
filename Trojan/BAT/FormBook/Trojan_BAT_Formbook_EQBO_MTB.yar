
rule Trojan_BAT_Formbook_EQBO_MTB{
	meta:
		description = "Trojan:BAT/Formbook.EQBO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 06 07 06 91 08 06 11 04 5d ?? ?? ?? ?? ?? 61 d2 9c 06 17 58 0a 06 07 8e 69 32 e4 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}