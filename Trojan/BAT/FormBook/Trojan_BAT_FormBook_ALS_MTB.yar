
rule Trojan_BAT_FormBook_ALS_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ALS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0c 16 13 05 2b 17 00 08 11 05 07 11 05 9a 1f 10 28 90 01 03 0a 9c 00 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 06 90 00 } //01 00 
		$a_01_1 = {43 00 65 00 6c 00 6c 00 75 00 6c 00 61 00 72 00 20 00 41 00 75 00 74 00 6f 00 6d 00 61 00 74 00 6f 00 6e 00 20 00 53 00 69 00 6d 00 75 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 } //00 00  Cellular Automaton Simulation
	condition:
		any of ($a_*)
 
}