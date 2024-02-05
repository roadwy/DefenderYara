
rule Trojan_BAT_NjRat_NECC_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NECC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {13 0f 11 0f 16 11 0e a2 00 11 0f 17 11 04 08 17 28 8f 00 00 0a a2 00 11 0f 18 11 06 08 17 28 8f 00 00 0a a2 00 11 0f 19 11 07 08 17 } //02 00 
		$a_01_1 = {45 00 6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74 00 } //02 00 
		$a_01_2 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //01 00 
		$a_01_3 = {46 6f 72 6d 31 5f 4c 6f 61 64 } //00 00 
	condition:
		any of ($a_*)
 
}