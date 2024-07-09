
rule Trojan_BAT_Formbook_SPA_MTB{
	meta:
		description = "Trojan:BAT/Formbook.SPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 08 05 08 9a 28 ?? ?? ?? 06 a2 08 17 58 0c 08 05 8e 69 32 eb } //2
		$a_03_1 = {72 a9 01 00 70 02 72 5f 00 00 70 17 8d 01 00 00 01 0d 09 16 07 8c 05 00 00 01 a2 09 28 ?? ?? ?? 06 0c 07 17 58 0b 72 75 01 00 70 06 72 c9 01 00 70 17 8d 01 00 00 01 13 04 11 04 16 08 a2 11 04 28 ?? ?? ?? 06 26 de b8 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}