
rule Trojan_Win64_CavernToffee_E_dha{
	meta:
		description = "Trojan:Win64/CavernToffee.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {5c 00 44 00 48 8d 55 90 01 01 66 44 89 75 90 01 01 48 8d 4d 90 01 01 c7 45 90 01 01 65 00 76 00 c7 45 90 01 01 69 00 63 00 c7 45 90 01 01 65 00 5c 00 c7 45 90 01 01 48 00 74 00 c7 45 90 01 01 74 00 70 00 c7 45 90 01 01 5c 00 43 00 c7 45 90 01 01 6f 00 6d 00 c7 45 90 01 01 6d 00 75 00 c7 45 90 01 01 6e 00 69 00 c7 45 90 01 01 63 00 61 00 c7 45 90 01 01 74 00 69 00 c7 45 90 01 01 6f 00 6e 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}