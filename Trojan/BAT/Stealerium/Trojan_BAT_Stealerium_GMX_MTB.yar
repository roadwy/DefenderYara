
rule Trojan_BAT_Stealerium_GMX_MTB{
	meta:
		description = "Trojan:BAT/Stealerium.GMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {13 05 02 11 05 7d 90 01 04 00 72 90 01 04 02 7b 90 01 04 25 2d 04 26 14 2b 05 6f 90 01 03 0a 28 90 01 03 0a 17 28 90 01 03 06 26 00 de 00 90 00 } //05 00 
		$a_03_1 = {25 16 1f 2c 9d 6f 90 01 03 0a 0b 07 07 8e 69 17 59 9a 0c 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}