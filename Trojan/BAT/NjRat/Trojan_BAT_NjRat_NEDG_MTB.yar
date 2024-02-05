
rule Trojan_BAT_NjRat_NEDG_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {24 64 35 33 35 66 64 38 37 2d 33 62 31 30 2d 34 66 36 66 2d 62 63 36 32 2d 64 33 31 64 62 63 30 36 30 61 31 36 } //02 00 
		$a_01_1 = {44 65 32 69 35 53 70 74 69 69 74 70 37 74 46 59 36 4d 32 } //02 00 
		$a_01_2 = {77 69 6e 64 6f 77 74 69 6d 65 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}