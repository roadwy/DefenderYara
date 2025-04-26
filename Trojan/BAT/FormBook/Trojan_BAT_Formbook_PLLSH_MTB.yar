
rule Trojan_BAT_Formbook_PLLSH_MTB{
	meta:
		description = "Trojan:BAT/Formbook.PLLSH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 19 32 50 0f 01 28 ?? 01 00 0a 1f 10 62 0f 01 28 ?? 01 00 0a 1e 62 60 0f 01 28 ?? 01 00 0a 60 0a 02 19 8d ?? 00 00 01 25 16 06 1f 10 63 20 ?? 00 00 00 5f d2 9c 25 17 06 1e 63 20 ?? 00 00 00 5f d2 9c 25 18 06 20 ?? 00 00 00 5f d2 9c 6f ?? 01 00 0a 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}