
rule Trojan_BAT_SolarMarker_AVN_MTB{
	meta:
		description = "Trojan:BAT/SolarMarker.AVN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {16 13 0c 2b 53 00 11 08 17 58 07 5d 13 08 11 09 11 07 11 08 94 58 07 5d 13 09 11 07 11 08 94 13 0a 11 07 11 08 11 07 11 09 94 9e 11 07 11 09 11 0a 9e 11 07 11 07 11 08 94 11 07 11 09 94 58 07 5d 94 13 0d 11 0b 11 0c 02 11 0c 91 11 0d 61 d2 9c 00 11 0c 17 58 13 0c 11 0c 02 8e 69 fe 04 13 0f 11 0f 2d a0 } //00 00 
	condition:
		any of ($a_*)
 
}