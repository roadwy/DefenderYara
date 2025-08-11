
rule Trojan_BAT_Formbook_BR_MTB{
	meta:
		description = "Trojan:BAT/Formbook.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 9a 16 99 5a a1 25 17 } //3
		$a_01_1 = {16 99 d2 9c 25 17 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}