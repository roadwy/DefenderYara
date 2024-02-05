
rule Trojan_BAT_ClipBanker_AV_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {08 16 06 6f 37 00 00 0a 6f 29 00 00 0a 13 05 06 11 05 6f 38 00 00 0a 13 06 07 11 06 6f 39 00 00 0a 26 00 11 04 17 58 13 04 11 04 02 fe 02 16 fe 01 13 07 11 07 2d c8 } //03 00 
		$a_80_1 = {43 68 65 63 6b 49 66 49 6e 66 65 63 74 65 64 } //CheckIfInfected  03 00 
		$a_80_2 = {50 61 79 6c 6f 61 64 } //Payload  03 00 
		$a_80_3 = {4c 69 6d 65 55 53 42 4d 6f 64 75 6c 65 } //LimeUSBModule  03 00 
		$a_80_4 = {69 6e 66 65 63 74 65 64 46 69 6c 65 } //infectedFile  00 00 
	condition:
		any of ($a_*)
 
}