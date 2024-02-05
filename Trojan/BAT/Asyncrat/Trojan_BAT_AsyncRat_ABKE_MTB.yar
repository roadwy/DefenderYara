
rule Trojan_BAT_AsyncRat_ABKE_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.ABKE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {04 07 09 16 6f 90 01 03 0a 13 04 12 04 28 90 01 03 0a 6f 90 01 03 0a 00 09 17 d6 0d 09 08 3e 90 00 } //01 00 
		$a_01_1 = {47 65 74 50 69 78 65 6c } //01 00 
		$a_01_2 = {54 6f 41 72 72 61 79 } //00 00 
	condition:
		any of ($a_*)
 
}