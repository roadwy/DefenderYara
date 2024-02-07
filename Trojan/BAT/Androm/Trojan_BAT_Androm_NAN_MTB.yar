
rule Trojan_BAT_Androm_NAN_MTB{
	meta:
		description = "Trojan:BAT/Androm.NAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {13 1a 11 1a 2c 30 11 04 72 90 01 02 00 70 6f 90 01 02 00 0a 26 11 04 6f 90 01 02 00 0a 28 90 01 02 00 0a 16 fe 01 13 1b 11 1b 2c 0d 11 04 6f 90 01 02 00 0a 28 90 01 02 00 0a 26 00 72 90 01 02 00 70 11 04 09 28 90 01 02 00 0a 28 90 01 02 00 0a 13 1c 11 1c 2c 24 02 7e 90 01 02 00 04 72 90 01 02 00 70 6f 90 01 02 00 0a 09 6f 90 01 02 00 0a 28 90 01 02 00 0a 28 90 01 02 00 06 00 00 2b 18 00 08 16 9a 72 90 01 02 00 70 11 04 90 00 } //01 00 
		$a_01_1 = {42 6f 73 63 68 2d 45 43 55 2d 55 6c 74 69 6d 61 58 2d 54 6f 6f 6c } //00 00  Bosch-ECU-UltimaX-Tool
	condition:
		any of ($a_*)
 
}