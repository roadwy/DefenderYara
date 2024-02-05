
rule Trojan_BAT_ArkeiStealer_AAHL_MTB{
	meta:
		description = "Trojan:BAT/ArkeiStealer.AAHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {0a 25 17 28 90 01 01 00 00 06 25 18 6f 90 01 01 00 00 0a 25 11 00 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 11 01 16 11 01 8e 69 28 90 01 01 00 00 06 13 03 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00 
	condition:
		any of ($a_*)
 
}