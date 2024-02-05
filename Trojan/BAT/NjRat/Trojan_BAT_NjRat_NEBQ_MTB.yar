
rule Trojan_BAT_NjRat_NEBQ_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEBQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {7e 09 00 00 04 08 07 28 2b 00 00 0a 16 6f 2c 00 00 0a 13 05 12 05 28 2d 00 00 0a 6f 2e 00 00 0a 00 07 09 12 01 28 2f 00 00 0a 13 06 11 06 2d d0 } //02 00 
		$a_01_1 = {6c 6f 61 64 4d } //02 00 
		$a_01_2 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 41 00 70 00 70 00 31 00 } //00 00 
	condition:
		any of ($a_*)
 
}