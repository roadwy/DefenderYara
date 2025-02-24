
rule Trojan_BAT_Formbook_KAU_MTB{
	meta:
		description = "Trojan:BAT/Formbook.KAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 16 11 0e 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 0e 1e 63 20 ff 00 00 00 5f d2 9c 25 18 11 0e 20 ff 00 00 00 5f d2 9c 6f ?? 00 00 0a 11 0f 16 94 } //1
		$a_03_1 = {25 16 12 0a 28 ?? 00 00 0a 9c 25 17 12 0a 28 ?? 00 00 0a 9c 25 18 12 0a 28 ?? 00 00 0a 9c 11 0b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}