
rule Trojan_BAT_AtlantidaStealer_RPX_MTB{
	meta:
		description = "Trojan:BAT/AtlantidaStealer.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 07 20 00 00 01 00 34 0f 07 2c 06 07 09 11 07 d1 9d 09 17 58 0d 2b 3d 11 07 20 ff ff 10 00 35 34 11 07 20 00 00 01 00 59 13 07 07 2c 23 07 09 20 00 d8 00 00 11 07 1f 0a 64 58 d1 9d 07 09 17 58 20 00 dc 00 00 11 07 20 ff 03 00 00 5f 58 d1 9d 09 18 58 0d 11 04 04 3f fa fe ff ff } //01 00 
		$a_01_1 = {61 00 63 00 74 00 69 00 76 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 70 00 68 00 70 00 3f 00 63 00 6f 00 64 00 65 00 3d 00 } //01 00  activation.php?code=
		$a_01_2 = {4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 35 00 2e 00 30 00 } //00 00  Mozilla/5.0
	condition:
		any of ($a_*)
 
}