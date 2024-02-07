
rule Trojan_BAT_Formbook_NWV_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NWV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 25 0b 19 5e 45 03 00 00 00 11 00 00 00 02 00 00 00 e0 ff ff ff 2b 0f 07 } //01 00 
		$a_01_1 = {24 31 33 64 34 34 61 30 64 2d 31 30 37 63 2d 34 37 33 65 2d 39 32 66 33 2d 30 35 30 62 31 36 37 38 61 38 30 63 } //00 00  $13d44a0d-107c-473e-92f3-050b1678a80c
	condition:
		any of ($a_*)
 
}