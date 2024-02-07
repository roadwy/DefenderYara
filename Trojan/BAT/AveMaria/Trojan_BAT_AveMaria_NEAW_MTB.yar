
rule Trojan_BAT_AveMaria_NEAW_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {13 13 16 13 15 11 13 28 90 01 02 00 06 11 15 18 d6 5d 6f 90 01 01 00 00 0a 11 15 17 d6 13 15 11 15 1f 0a 31 e3 90 00 } //05 00 
		$a_03_1 = {11 13 1b 11 13 1b 6f 90 01 01 00 00 0a 1f 19 d8 1f 19 d8 6f 90 00 } //02 00 
		$a_01_2 = {7b 00 30 00 7d 00 3a 00 2f 00 2f 00 7b 00 31 00 7d 00 2e 00 7b 00 32 00 7d 00 2e 00 7b 00 33 00 7d 00 } //00 00  {0}://{1}.{2}.{3}
	condition:
		any of ($a_*)
 
}