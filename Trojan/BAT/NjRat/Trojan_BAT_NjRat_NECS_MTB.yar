
rule Trojan_BAT_NjRat_NECS_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NECS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {28 9d 00 00 0a 02 11 50 28 9e 00 00 0a 72 65 37 01 70 18 18 6f 3c 00 00 06 6f 9f 00 00 0a 13 54 11 54 14 } //02 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //02 00 
		$a_01_2 = {49 00 6e 00 74 00 65 00 6c 00 6c 00 69 00 4c 00 6f 00 63 00 6b 00 } //00 00 
	condition:
		any of ($a_*)
 
}