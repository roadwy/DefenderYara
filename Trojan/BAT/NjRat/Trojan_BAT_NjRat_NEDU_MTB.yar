
rule Trojan_BAT_NjRat_NEDU_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEDU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {d8 b7 0c 0b 2b 37 02 50 07 02 50 8e b7 5d 02 50 07 02 50 8e b7 5d 91 03 07 03 8e b7 5d 91 61 02 50 07 17 d6 02 50 8e b7 5d 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c 07 17 d6 0b 07 08 31 c5 02 02 50 8e b7 17 da } //04 00 
		$a_01_1 = {50 6f 6c 79 44 65 43 72 79 70 74 } //00 00 
	condition:
		any of ($a_*)
 
}