
rule Trojan_BAT_njRAT_MBAW_MTB{
	meta:
		description = "Trojan:BAT/njRAT.MBAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 7e 90 02 20 0a 00 08 18 6f 90 01 01 00 00 0a 00 28 90 01 01 00 00 0a 08 6f 90 01 01 00 00 0a 07 16 07 8e b7 6f 6d 00 00 0a 90 00 } //01 00 
		$a_01_1 = {23 06 2d 06 46 06 2d 06 44 06 2c 06 48 06 46 06 2e 06 46 06 46 06 48 06 2c 06 31 06 23 06 43 06 43 06 46 06 43 06 31 06 31 06 2c 06 46 06 31 06 31 06 31 06 44 06 2d 06 31 06 2f 06 31 } //01 00 
		$a_01_2 = {62 35 66 32 36 62 65 31 30 33 62 } //00 00  b5f26be103b
	condition:
		any of ($a_*)
 
}