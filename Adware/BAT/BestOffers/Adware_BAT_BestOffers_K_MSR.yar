
rule Adware_BAT_BestOffers_K_MSR{
	meta:
		description = "Adware:BAT/BestOffers.K!MSR,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 68 65 62 65 73 74 6f 66 66 65 72 73 69 6e } //01 00 
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00 
		$a_01_2 = {2f 56 45 52 59 53 49 4c 45 4e 54 } //00 00 
	condition:
		any of ($a_*)
 
}