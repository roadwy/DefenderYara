
rule Trojan_BAT_Injuke_CCHE_MTB{
	meta:
		description = "Trojan:BAT/Injuke.CCHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {25 11 04 28 90 01 01 03 00 06 00 25 17 28 90 01 01 03 00 06 00 25 18 28 90 01 01 03 00 06 00 25 07 28 90 01 01 03 00 06 00 13 08 20 90 01 01 00 00 00 38 90 01 01 fe ff ff 08 11 04 73 90 01 04 09 07 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}