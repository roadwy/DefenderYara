
rule Trojan_BAT_Stealerc_AAES_MTB{
	meta:
		description = "Trojan:BAT/Stealerc.AAES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {13 05 00 11 05 6f 90 01 01 00 00 0a 13 06 11 06 08 6f 90 01 01 00 00 0a 00 08 6f 90 01 01 00 00 0a 03 6a da 17 6a da 13 07 16 6a 13 08 2b 0f 07 16 6f 90 01 01 00 00 0a 00 11 08 17 6a d6 13 08 11 08 11 07 31 eb de 0e 00 11 06 2c 08 11 06 6f 90 01 01 00 00 0a 00 dc 90 00 } //02 00 
		$a_03_1 = {16 13 04 2b 1d 07 02 11 04 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 11 04 18 d6 13 04 11 04 09 31 de 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}