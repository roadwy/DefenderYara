
rule Trojan_BAT_Bladabindi_NEAA_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {74 24 00 00 01 6f 20 00 00 0a 07 6f 21 00 00 0a 2c 12 2b 06 0b 2b ba 0c 2b c0 08 16 6f 1f 00 00 0a 0a 2b 6d 08 17 } //05 00 
		$a_01_1 = {2b 03 2b 08 2a 28 04 00 00 06 2b f6 28 1d 00 00 0a 2b f1 } //02 00 
		$a_01_2 = {50 6f 77 65 72 65 64 20 62 79 20 53 6d 61 72 74 41 73 73 65 6d 62 6c 79 20 38 2e 31 2e 30 2e 34 38 39 32 } //00 00  Powered by SmartAssembly 8.1.0.4892
	condition:
		any of ($a_*)
 
}