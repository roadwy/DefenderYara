
rule Trojan_BAT_NjRat_NECL_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NECL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {28 0d 00 00 0a 28 0e 00 00 0a d0 11 00 00 01 28 0f 00 00 0a 72 90 01 01 00 00 70 28 10 00 00 0a 0a 16 8c 90 01 01 00 00 01 0b 17 8d 90 01 01 00 00 01 0d 09 16 90 00 } //02 00 
		$a_01_1 = {45 00 6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74 00 } //02 00  EntryPoint
		$a_01_2 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //00 00  Invoke
	condition:
		any of ($a_*)
 
}