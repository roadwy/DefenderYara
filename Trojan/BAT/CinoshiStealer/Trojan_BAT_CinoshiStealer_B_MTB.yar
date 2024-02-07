
rule Trojan_BAT_CinoshiStealer_B_MTB{
	meta:
		description = "Trojan:BAT/CinoshiStealer.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {57 ff a2 ff 09 0e 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 9c 00 00 00 b2 00 00 00 a2 03 00 00 46 07 } //02 00 
		$a_01_1 = {49 6f 6e 69 63 2e 5a 69 70 } //02 00  Ionic.Zip
		$a_01_2 = {43 72 65 64 69 74 43 61 72 64 73 4e 6f 74 46 6f 75 6e 64 } //00 00  CreditCardsNotFound
	condition:
		any of ($a_*)
 
}