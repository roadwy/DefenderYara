
rule Trojan_BAT_Toshruli_A{
	meta:
		description = "Trojan:BAT/Toshruli.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 61 6b 65 33 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00  fake3.Properties.Resources
		$a_03_1 = {20 b8 0b 00 00 28 90 01 01 00 00 0a 11 04 2d a1 20 90 01 04 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 13 06 11 06 20 90 01 04 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 90 00 } //01 00 
		$a_03_2 = {38 0e 00 00 00 11 0e 6f 90 01 01 00 00 0a 26 11 0f 17 58 13 0f 11 0f 20 18 04 00 00 32 e9 11 0e 20 90 01 04 28 90 01 01 00 00 06 6f 90 01 01 00 00 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}