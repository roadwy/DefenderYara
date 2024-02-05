
rule Trojan_BAT_Injector_NPMP_MTB{
	meta:
		description = "Trojan:BAT/Injector.NPMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {5a 19 5a 8d 21 00 00 01 0a 16 0b 02 6f 90 01 03 0a 17 59 0d 2b 5a 00 16 13 04 2b 3f 00 02 11 04 09 6f 90 01 03 0a 13 05 06 07 19 5a 18 58 12 05 28 90 01 03 0a 9c 06 07 19 5a 17 58 12 05 28 90 01 03 0a 9c 06 07 19 5a 12 05 28 90 01 03 0a 9c 07 17 58 0b 00 11 04 17 58 13 04 11 04 02 6f 90 01 03 0a fe 04 13 06 11 06 2d b1 00 09 17 59 0d 09 16 fe 04 16 fe 01 13 07 11 07 2d 99 06 16 28 90 01 03 0a 8d 21 00 00 01 0c 06 1a 08 16 08 8e 69 28 90 01 03 0a 00 08 13 08 2b 00 11 08 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}