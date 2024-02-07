
rule Trojan_BAT_AveMaria_NEAD_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {14 14 14 28 32 00 00 0a 28 38 00 00 0a 72 90 01 01 01 00 70 28 38 00 00 0a 02 7b 90 01 01 00 00 04 14 72 53 00 00 70 16 8d 03 00 00 01 90 00 } //01 00 
		$a_01_1 = {6a 00 68 00 64 00 61 00 66 00 69 00 6f 00 6f 00 65 00 79 00 74 00 38 00 65 00 39 00 77 00 74 00 37 00 77 00 } //00 00  jhdafiooeyt8e9wt7w
	condition:
		any of ($a_*)
 
}