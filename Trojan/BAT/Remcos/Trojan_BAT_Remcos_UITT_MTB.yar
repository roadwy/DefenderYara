
rule Trojan_BAT_Remcos_UITT_MTB{
	meta:
		description = "Trojan:BAT/Remcos.UITT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {73 18 00 00 0a 0b 73 30 00 00 0a 0d 00 20 98 3a 02 c9 25 13 04 13 05 16 13 0f 00 11 05 20 69 c5 fd 36 58 13 04 00 11 04 16 fe 01 16 fe 01 13 06 11 06 2d 03 16 2b 01 17 00 13 07 20 96 02 3d 9b 25 13 08 13 09 16 13 0f 00 11 09 20 6a fd c2 64 58 13 08 00 11 07 11 08 fe 01 13 0f 11 0f 2d 0f 00 06 09 7e 01 00 00 04 28 90 01 03 06 00 00 09 13 0a 20 8e f0 3a 8f 25 13 0b 13 0c 16 13 0f 00 11 0c 20 72 0f c5 70 58 13 0b 00 11 0a 11 0b 6a 6f 90 01 03 0a 00 09 73 32 00 00 0a 13 0d 11 0d 28 90 01 03 06 0c 00 de 12 09 14 fe 01 13 0f 11 0f 2d 07 09 6f 90 01 03 0a 00 dc 00 08 13 0e 2b 00 11 0e 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}