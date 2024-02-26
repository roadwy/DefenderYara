
rule Trojan_BAT_StealC_CCES_MTB{
	meta:
		description = "Trojan:BAT/StealC.CCES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {5d 0c 08 16 2f 08 08 20 90 01 04 58 0c 06 07 08 d1 9d 07 17 58 0b 07 02 6f 90 01 01 00 00 0a 32 d2 90 00 } //01 00 
		$a_03_1 = {02 07 91 0c 03 07 03 6f 90 01 01 00 00 0a 5d 6f 90 01 01 00 00 0a d2 0d 08 09 28 90 01 01 01 00 06 13 04 06 07 11 04 9c 00 07 17 58 0b 07 02 8e 69 fe 04 13 05 11 05 2d cc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}