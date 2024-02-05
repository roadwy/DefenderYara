
rule Trojan_BAT_AsyncRat_NEAN_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NEAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {2b 24 11 05 06 8f 90 01 01 00 00 01 25 71 90 01 01 00 00 01 06 0e 04 58 20 90 01 01 00 00 00 5f d2 61 d2 81 90 01 01 00 00 01 06 17 58 0a 06 04 32 d8 90 00 } //05 00 
		$a_01_1 = {53 45 5a 4e 41 4d 5f 53 54 45 41 4d } //00 00 
	condition:
		any of ($a_*)
 
}