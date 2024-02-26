
rule Trojan_BAT_Remcos_ARM_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 38 16 0b 2b 21 08 06 07 28 90 01 03 06 13 09 09 12 09 28 90 01 03 0a 8c 07 00 00 01 28 90 01 03 06 26 07 17 58 0b 07 08 28 90 01 03 06 fe 04 13 06 11 06 2d d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Remcos_ARM_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 02 8e 69 20 00 10 00 00 1f 40 28 90 01 01 00 00 06 0a 16 0b 25 06 02 02 8e 69 12 01 28 90 01 01 00 00 06 26 7e 90 01 01 00 00 0a 0c 7e 90 01 01 00 00 0a 16 20 ff 0f 00 00 28 90 01 01 00 00 0a 7e 90 01 01 00 00 0a 1a 12 02 28 90 00 } //01 00 
		$a_01_1 = {0a 16 0b 2b 22 06 07 9a 0c 08 6f 2f 00 00 0a 6f 30 00 00 0a 02 28 14 00 00 0a 2c 07 08 6f 31 00 00 0a 2a 07 17 58 0b 07 06 8e 69 32 d8 } //00 00 
	condition:
		any of ($a_*)
 
}