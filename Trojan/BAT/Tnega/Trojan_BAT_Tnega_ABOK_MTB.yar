
rule Trojan_BAT_Tnega_ABOK_MTB{
	meta:
		description = "Trojan:BAT/Tnega.ABOK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {0a 16 fe 01 0c 08 2c 19 7e 90 01 03 04 28 90 01 03 06 28 90 01 03 2b 28 90 01 03 2b 0b 07 0a 2b 01 00 06 2a 90 0a 33 00 28 90 01 03 06 72 90 01 03 70 16 28 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_2 = {4d 00 65 00 74 00 72 00 6f 00 70 00 6f 00 6c 00 69 00 73 00 5f 00 4c 00 61 00 75 00 6e 00 63 00 68 00 65 00 72 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00  Metropolis_Launcher.Resources
	condition:
		any of ($a_*)
 
}