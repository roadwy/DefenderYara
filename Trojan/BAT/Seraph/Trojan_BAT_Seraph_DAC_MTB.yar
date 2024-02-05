
rule Trojan_BAT_Seraph_DAC_MTB{
	meta:
		description = "Trojan:BAT/Seraph.DAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 03 00 "
		
	strings :
		$a_03_0 = {26 07 18 5b 8d 02 00 00 01 1a 2d 0b 26 16 0d 2b 21 0a 2b e3 0b 2b ea 0c 2b f3 08 09 18 5b 06 09 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 9c 09 18 58 0d 09 07 32 e4 90 00 } //03 00 
		$a_03_1 = {26 07 18 5b 8d 02 00 00 01 1e 2d 0b 26 16 0d 2b 21 0a 2b e3 0b 2b ea 0c 2b f3 08 09 18 5b 06 09 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 9c 09 18 58 0d 09 07 32 e4 90 00 } //01 00 
		$a_01_2 = {54 6f 42 79 74 65 } //01 00 
		$a_01_3 = {53 75 62 73 74 72 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}