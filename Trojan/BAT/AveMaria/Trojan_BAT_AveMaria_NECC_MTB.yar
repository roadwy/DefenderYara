
rule Trojan_BAT_AveMaria_NECC_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NECC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {14 14 14 2b 11 74 90 01 01 00 00 01 2b 11 16 2d da 16 2d d7 2a 02 2b db 6f 90 01 01 00 00 0a 2b e8 28 90 01 01 00 00 0a 2b e8 90 00 } //05 00 
		$a_03_1 = {00 00 0a 13 04 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 73 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 16 6a 31 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}