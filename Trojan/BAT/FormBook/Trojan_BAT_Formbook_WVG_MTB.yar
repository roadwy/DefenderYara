
rule Trojan_BAT_Formbook_WVG_MTB{
	meta:
		description = "Trojan:BAT/Formbook.WVG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {19 8d 3b 00 00 01 25 16 02 7c 3c 00 00 04 28 7d 00 00 0a 9c 25 17 02 7c 3c 00 00 04 28 7f 00 00 0a 9c 25 18 02 7c 3c 00 00 04 28 ?? 00 00 0a 9c 0a 09 20 00 6b 69 29 5a 20 2c d3 66 d3 61 38 cf fe ff ff } //5
		$a_03_1 = {11 0e 02 11 0b 11 0d 6f ?? 00 00 0a 7d 3c 00 00 04 11 0e 04 11 0e 7b 3e 00 00 04 7b 3b 00 00 04 6f ?? 00 00 0a 59 7d 3d 00 00 04 11 17 20 d6 38 3e 23 5a 20 8e 2b d1 3b 61 38 ab fb ff ff } //4
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*4) >=9
 
}