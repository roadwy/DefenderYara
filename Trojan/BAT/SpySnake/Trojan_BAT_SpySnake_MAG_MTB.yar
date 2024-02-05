
rule Trojan_BAT_SpySnake_MAG_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {1d 2d 0b 2b 41 02 8e 69 1c 2d 06 26 2b 0d 0a 2b f4 0b 2b f8 06 07 02 07 91 2b 0e 07 25 17 59 17 2d 13 26 16 fe 02 0c 2b 07 6f 90 01 03 0a 2b eb 08 2d e1 2b 03 0b 2b eb 90 00 } //01 00 
		$a_01_1 = {54 6f 41 72 72 61 79 } //01 00 
		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00 
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00 
		$a_01_4 = {59 00 6b 00 6e 00 62 00 68 00 70 00 73 00 6a 00 6b 00 78 00 69 00 71 00 72 00 7a 00 76 00 79 00 7a 00 61 00 6f 00 76 00 62 00 } //00 00 
	condition:
		any of ($a_*)
 
}