
rule Trojan_BAT_DCRat_G_MTB{
	meta:
		description = "Trojan:BAT/DCRat.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {2f 00 63 00 20 00 53 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 20 00 2f 00 72 00 20 00 2f 00 66 00 20 00 2f 00 74 00 } //02 00 
		$a_01_1 = {57 ff b7 3f 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 4b 01 00 00 26 06 00 00 3c 06 00 00 b5 0e } //00 00 
	condition:
		any of ($a_*)
 
}