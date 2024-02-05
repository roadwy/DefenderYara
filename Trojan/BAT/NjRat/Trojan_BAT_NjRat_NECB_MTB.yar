
rule Trojan_BAT_NjRat_NECB_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NECB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {28 59 00 00 0a 11 68 28 5a 00 00 0a 6f 5b 00 00 0a 0a 06 14 72 7b 24 01 70 16 8d 03 00 00 01 14 14 14 28 5c 00 00 0a 14 } //02 00 
		$a_01_1 = {45 00 6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74 00 } //02 00 
		$a_01_2 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //01 00 
		$a_01_3 = {46 6f 72 6d 31 5f 4c 6f 61 64 } //00 00 
	condition:
		any of ($a_*)
 
}