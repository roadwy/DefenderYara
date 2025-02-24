
rule Trojan_BAT_Formbook_KAW_MTB{
	meta:
		description = "Trojan:BAT/Formbook.KAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {25 16 02 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 02 1e 63 20 ff 00 00 00 5f d2 9c 25 18 02 20 ff 00 00 00 5f d2 9c 0a 2b 00 } //3
		$a_03_1 = {25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 0a 2b 00 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}