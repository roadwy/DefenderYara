
rule Trojan_BAT_Formbook_PLIEH_MTB{
	meta:
		description = "Trojan:BAT/Formbook.PLIEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 1f 10 62 0f 00 28 ?? 00 00 0a 1e 62 60 0f 00 28 ?? 00 00 0a 60 0a 03 19 8d ?? 00 00 01 25 16 06 1f 10 63 20 ?? 00 00 00 5f d2 9c 25 17 06 1e 63 20 ?? 00 00 00 5f d2 9c 25 18 06 20 ?? 00 00 00 5f d2 9c 6f ?? 00 00 0a 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}