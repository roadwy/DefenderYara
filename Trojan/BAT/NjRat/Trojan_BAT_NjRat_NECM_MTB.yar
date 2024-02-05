
rule Trojan_BAT_NjRat_NECM_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NECM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {28 96 00 00 0a 11 38 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 13 39 11 39 14 72 90 01 01 e2 03 70 16 8d 05 00 00 01 14 14 14 28 99 00 00 0a 14 72 90 01 01 e2 03 70 18 8d 05 00 00 01 13 3b 11 3b 16 14 a2 00 11 3b 17 14 a2 00 11 3b 14 14 14 90 00 } //02 00 
		$a_01_1 = {45 00 6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74 00 } //02 00 
		$a_01_2 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}