
rule Trojan_BAT_AveMaria_NECF_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NECF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {2b 05 2b 0a 2b 0f 2a 28 90 01 01 00 00 0a 2b f4 28 90 01 01 00 00 2b 2b ef 28 90 01 01 00 00 2b 2b ea 90 00 } //05 00 
		$a_03_1 = {11 08 17 58 13 08 11 08 11 07 8e 69 32 c4 2a 73 90 01 01 00 00 0a 38 13 ff ff ff 0a 38 12 ff ff ff 28 90 01 01 00 00 0a 38 0d ff ff ff 28 90 01 01 00 00 06 38 08 ff ff ff 6f 90 01 01 00 00 0a 38 03 ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}