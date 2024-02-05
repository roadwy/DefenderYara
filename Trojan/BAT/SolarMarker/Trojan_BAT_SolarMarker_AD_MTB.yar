
rule Trojan_BAT_SolarMarker_AD_MTB{
	meta:
		description = "Trojan:BAT/SolarMarker.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_81_0 = {5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 73 6f 6c 61 72 6d 61 72 6b 65 72 2e 64 61 74 } //01 00 
		$a_81_1 = {39 33 65 36 39 62 31 35 2d 66 34 64 62 2d 34 61 63 61 2d 39 37 33 38 2d 65 33 62 62 64 63 65 33 66 65 63 31 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}