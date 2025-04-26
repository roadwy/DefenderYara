
rule Trojan_BAT_Formbook_PQIH_MTB{
	meta:
		description = "Trojan:BAT/Formbook.PQIH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 16 11 18 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 18 1e 63 20 ff 00 00 00 5f d2 9c 25 18 11 18 20 ff 00 00 00 5f d2 9c 6f ?? 00 00 0a 00 11 19 16 94 } //6
		$a_03_1 = {25 16 12 0c 28 ?? 00 00 0a 9c 25 17 12 0c 28 ?? 00 00 0a 9c 25 18 12 0c 28 ?? 00 00 0a 9c 11 0e } //5
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}