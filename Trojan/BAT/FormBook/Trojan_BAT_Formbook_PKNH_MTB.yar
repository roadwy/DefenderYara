
rule Trojan_BAT_Formbook_PKNH_MTB{
	meta:
		description = "Trojan:BAT/Formbook.PKNH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 16 11 0c 1f 10 63 20 ?? 00 00 00 5f d2 9c 25 17 11 0c 1e 63 20 ?? 00 00 00 5f d2 9c 25 18 11 0c 20 ?? 00 00 00 5f d2 9c } //6
		$a_03_1 = {30 02 2b 68 11 05 20 ?? 07 00 00 5a 11 09 61 13 05 08 1f 1f 62 08 1f 21 64 60 0c 03 19 8d ?? 00 00 01 25 16 12 06 28 ?? 00 00 0a 9c 25 17 12 06 28 ?? 00 00 0a 9c 25 18 12 06 28 ?? 00 00 0a 9c 11 08 } //4
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*4) >=10
 
}