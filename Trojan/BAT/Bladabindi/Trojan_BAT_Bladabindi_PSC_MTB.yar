
rule Trojan_BAT_Bladabindi_PSC_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.PSC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {0a 06 28 30 00 00 0a 2d 12 06 28 90 01 03 06 28 90 01 03 0a 06 28 90 01 03 0a 26 06 28 90 01 03 0a 2c 0e 06 18 28 90 01 03 0a 06 28 90 01 03 0a 26 28 90 01 03 0a 72 90 01 03 70 28 90 01 03 0a 0c 28 90 01 03 06 0b 08 28 90 01 03 0a 2c 07 08 90 00 } //01 00 
		$a_01_1 = {47 65 74 4f 62 6a 65 63 74 } //01 00 
		$a_01_2 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //00 00 
	condition:
		any of ($a_*)
 
}