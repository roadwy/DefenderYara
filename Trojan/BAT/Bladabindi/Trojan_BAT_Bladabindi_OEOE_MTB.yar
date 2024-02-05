
rule Trojan_BAT_Bladabindi_OEOE_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.OEOE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0a 1f 2a 1f 30 28 90 01 03 0a 0b 07 28 90 01 03 06 0c 08 28 90 01 03 0a 6f 90 01 03 0a 14 14 6f 90 01 03 0a 26 2a 90 00 } //01 00 
		$a_02_1 = {06 0a 06 02 7d 90 01 03 04 00 16 06 7b 90 01 03 04 6f 90 01 03 0a 28 90 01 03 0a 7e 90 01 03 04 25 2d 17 26 7e 90 01 03 04 fe 90 01 04 06 73 90 01 03 0a 25 80 90 01 03 04 28 90 01 03 2b 06 fe 90 01 04 06 73 90 01 03 0a 28 90 01 03 2b 28 90 01 03 2b 0b 2b 00 07 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}