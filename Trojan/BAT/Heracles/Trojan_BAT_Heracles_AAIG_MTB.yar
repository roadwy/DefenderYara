
rule Trojan_BAT_Heracles_AAIG_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AAIG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 1c 5d 16 fe 01 0d 09 2c 08 1d 13 07 38 90 01 01 ff ff ff 1f 09 2b f5 03 17 8d 90 01 01 00 00 01 25 16 07 8c 90 01 01 00 00 01 a2 14 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 13 04 17 13 07 38 90 01 01 ff ff ff 03 18 8d 90 01 01 00 00 01 25 16 07 8c 90 01 01 00 00 01 a2 25 17 11 04 6a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}