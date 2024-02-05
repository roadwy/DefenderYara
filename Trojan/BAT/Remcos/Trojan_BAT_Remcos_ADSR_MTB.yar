
rule Trojan_BAT_Remcos_ADSR_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ADSR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {15 0d 00 08 1f 3c 09 17 58 6f 90 01 03 0a 0d 09 15 fe 01 16 fe 01 13 04 11 04 2c 4c 00 08 1f 3e 09 6f 90 01 03 0a 13 05 11 05 15 fe 01 16 fe 01 13 06 11 06 2c 31 00 11 05 09 59 13 07 08 09 17 58 11 07 17 59 6f 90 01 03 0a 13 08 02 7b 58 00 00 04 6f 90 01 03 0a 09 17 58 11 07 17 59 11 08 6f 90 01 03 0a 26 00 00 00 09 15 fe 01 16 fe 01 13 09 11 09 2d 8c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}