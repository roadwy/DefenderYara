
rule Trojan_BAT_Remcos_AIGH_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AIGH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 36 00 07 08 09 28 90 01 03 06 28 90 01 03 06 00 28 90 01 03 06 28 90 01 03 06 28 90 01 03 06 00 17 13 04 00 28 90 01 03 06 d2 06 28 90 00 } //01 00 
		$a_01_1 = {4a 00 61 00 72 00 72 00 65 00 74 00 74 00 56 00 61 00 6e 00 63 00 65 00 2e 00 55 00 70 00 64 00 61 00 74 00 65 00 72 00 } //01 00  JarrettVance.Updater
		$a_01_2 = {43 00 61 00 72 00 67 00 6f 00 57 00 69 00 73 00 65 00 2e 00 57 00 68 00 69 00 74 00 65 00 } //00 00  CargoWise.White
	condition:
		any of ($a_*)
 
}