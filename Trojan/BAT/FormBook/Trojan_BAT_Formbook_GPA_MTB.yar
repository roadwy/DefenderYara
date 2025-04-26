
rule Trojan_BAT_Formbook_GPA_MTB{
	meta:
		description = "Trojan:BAT/Formbook.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {46 47 35 50 47 38 46 52 34 38 34 38 54 56 5a 33 41 35 47 5a 4f 34 } //1 FG5PG8FR4848TVZ3A5GZO4
		$a_01_1 = {17 58 07 8e 69 5d 91 13 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}