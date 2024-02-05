
rule Trojan_BAT_Bladabindi_DF_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 06 11 06 6f 24 00 00 0a 72 90 01 03 70 72 90 01 03 70 6f 25 00 00 0a 72 90 01 03 70 72 90 01 03 70 6f 25 00 00 0a 13 07 11 07 6f 24 00 00 0a 28 03 00 00 06 28 26 00 00 0a 72 90 01 03 70 28 06 00 00 06 13 08 11 08 17 28 02 00 00 06 00 00 06 17 58 0a 06 17 fe 04 13 0a 11 0a 3a da fe ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}