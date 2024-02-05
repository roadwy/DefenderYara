
rule Trojan_BAT_Seraph_GAS_MTB{
	meta:
		description = "Trojan:BAT/Seraph.GAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {14 16 2c 43 26 2b 3b 1d 2c 38 00 1a 2c 2c 7e 90 01 01 00 00 04 7e 90 01 01 00 00 04 7e 90 01 01 00 00 04 28 90 01 01 00 00 06 28 90 01 01 00 00 06 28 90 01 01 00 00 06 28 90 01 01 00 00 06 28 90 01 01 00 00 06 19 2d 03 26 de 06 0a 2b fb 26 de 00 06 2c c2 90 00 } //01 00 
		$a_01_1 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 } //00 00 
	condition:
		any of ($a_*)
 
}