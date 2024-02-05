
rule Trojan_BAT_PolyRansom_DE_MTB{
	meta:
		description = "Trojan:BAT/PolyRansom.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {51 74 62 78 67 7a 6c 61 } //03 00 
		$a_81_1 = {44 6f 77 5a 6e 6c 5a 6f 61 64 44 5a 61 74 61 } //03 00 
		$a_81_2 = {2f 43 20 74 69 6d 65 6f 75 74 20 32 30 } //03 00 
		$a_81_3 = {6e 65 77 2f 51 74 62 78 67 7a 6c 61 2e 6a 70 67 } //03 00 
		$a_81_4 = {53 6e 73 73 64 64 68 6f 68 71 63 6b 6f 66 71 79 63 76 79 79 6b 75 70 } //03 00 
		$a_81_5 = {53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c 54 79 70 65 } //03 00 
		$a_81_6 = {41 70 70 44 6f 6d 61 69 6e } //00 00 
	condition:
		any of ($a_*)
 
}