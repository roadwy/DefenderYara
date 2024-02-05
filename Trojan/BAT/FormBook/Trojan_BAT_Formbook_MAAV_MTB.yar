
rule Trojan_BAT_Formbook_MAAV_MTB{
	meta:
		description = "Trojan:BAT/Formbook.MAAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {37 00 45 00 79 00 66 00 35 00 49 00 4e 00 49 00 6e 00 61 00 62 00 72 00 44 00 46 00 68 00 48 00 45 00 2e 00 63 00 31 00 36 00 49 00 6b 00 30 00 32 00 4b 00 53 00 77 00 4c 00 6d 00 71 00 6f 00 42 00 46 00 44 00 79 } //00 00 
	condition:
		any of ($a_*)
 
}