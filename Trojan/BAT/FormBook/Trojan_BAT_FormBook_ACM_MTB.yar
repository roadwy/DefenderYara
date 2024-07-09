
rule Trojan_BAT_FormBook_ACM_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ACM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 04 2b 1e 08 11 04 9a 13 08 09 11 08 1f 10 28 ?? ?? ?? 0a b4 6f ?? ?? ?? 0a 00 11 04 17 d6 13 04 00 11 04 08 8e 69 fe 04 13 09 11 09 } //2
		$a_01_1 = {57 00 32 00 50 00 69 00 7a 00 7a 00 61 00 4f 00 72 00 64 00 65 00 72 00 } //1 W2PizzaOrder
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_FormBook_ACM_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.ACM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 11 08 06 11 08 9a 1f 10 28 ?? ?? ?? 0a 9c 11 08 17 58 13 08 11 08 06 8e 69 fe 04 13 09 11 09 2d de } //2
		$a_01_1 = {4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 43 00 68 00 65 00 63 00 6b 00 65 00 72 00 73 00 57 00 69 00 6e 00 46 00 6f 00 72 00 6d 00 73 00 } //1 NetworkCheckersWinForms
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}