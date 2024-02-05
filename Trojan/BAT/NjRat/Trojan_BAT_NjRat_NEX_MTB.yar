
rule Trojan_BAT_NjRat_NEX_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {fe 01 13 04 11 04 2d dc 28 90 01 01 00 00 0a 07 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 72 90 01 01 01 00 70 90 00 } //03 00 
		$a_01_1 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //01 00 
		$a_01_2 = {53 6c 65 65 70 } //00 00 
	condition:
		any of ($a_*)
 
}