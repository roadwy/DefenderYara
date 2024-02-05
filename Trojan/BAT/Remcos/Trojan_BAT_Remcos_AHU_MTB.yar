
rule Trojan_BAT_Remcos_AHU_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AHU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 1a 58 4a 03 8e 69 5d 03 06 1a 58 4a 03 8e 69 5d 91 07 06 1a 58 4a 07 8e 69 5d 91 61 28 90 01 03 0a 03 06 1a 58 4a 1f 15 58 1f 14 59 03 8e 69 5d 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 16 2d 8d 06 1a 58 06 1a 58 4a 17 58 54 06 1a 58 4a 6a 03 8e 69 17 59 6a 06 4b 17 58 6e 5a 31 98 0f 01 03 8e 69 17 59 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}