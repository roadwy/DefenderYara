
rule Trojan_BAT_DCRat_EAP_MTB{
	meta:
		description = "Trojan:BAT/DCRat.EAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {0c 16 13 05 2b 1c 00 08 11 05 07 11 05 9a 1f 10 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 00 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 06 11 06 2d d7 90 00 } //02 00 
		$a_01_1 = {57 00 51 00 4a 00 7a 00 6a 00 77 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}