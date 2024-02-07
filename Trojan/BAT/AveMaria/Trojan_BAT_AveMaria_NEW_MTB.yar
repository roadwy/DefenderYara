
rule Trojan_BAT_AveMaria_NEW_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 05 28 07 00 00 0a 13 06 28 08 00 00 0a 11 06 6f 09 00 00 0a 13 07 11 07 13 08 11 04 11 08 08 6f 0a 00 00 0a 07 08 19 17 73 24 1d 00 06 7d 8c 14 00 04 07 } //01 00 
		$a_01_1 = {3d 00 3d 00 46 00 6c 00 50 00 4b 00 30 00 64 00 75 00 52 00 63 00 76 00 6c 00 65 00 63 00 5a 00 54 00 67 00 } //01 00  ==FlPK0duRcvlecZTg
		$a_01_2 = {43 00 6f 00 6e 00 66 00 6c 00 69 00 63 00 74 00 69 00 6e 00 67 00 52 00 65 00 6e 00 64 00 65 00 72 00 53 00 74 00 61 00 74 00 65 00 45 00 78 00 63 00 65 00 70 00 74 00 69 00 6f 00 6e 00 2e 00 64 00 6c 00 6c 00 } //00 00  ConflictingRenderStateException.dll
	condition:
		any of ($a_*)
 
}