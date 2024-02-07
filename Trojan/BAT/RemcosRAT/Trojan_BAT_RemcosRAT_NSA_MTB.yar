
rule Trojan_BAT_RemcosRAT_NSA_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.NSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {38 58 00 00 00 11 01 28 90 01 01 00 00 0a 13 02 38 90 01 01 00 00 00 11 02 13 03 38 90 01 01 00 00 00 11 02 16 11 02 8e 69 28 11 00 00 0a 90 00 } //01 00 
		$a_01_1 = {4e 00 65 00 77 00 20 00 51 00 75 00 6f 00 74 00 65 00 20 00 4f 00 72 00 64 00 65 00 72 00 } //00 00  New Quote Order
	condition:
		any of ($a_*)
 
}