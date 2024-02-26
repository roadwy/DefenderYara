
rule Trojan_BAT_Crysan_SPQI_MTB{
	meta:
		description = "Trojan:BAT/Crysan.SPQI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {38 22 00 00 00 00 28 90 01 03 06 16 fe 01 0d 09 39 06 00 00 00 28 90 01 03 06 00 20 90 01 03 00 28 90 01 03 0a 00 00 17 13 04 38 d6 ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}