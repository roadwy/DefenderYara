
rule Trojan_BAT_Vidar_NHA_MTB{
	meta:
		description = "Trojan:BAT/Vidar.NHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {d0 16 00 00 01 28 90 01 02 00 06 02 28 90 01 02 00 06 75 90 01 02 00 1b 28 90 01 02 00 2b 20 90 01 02 00 00 28 90 01 02 00 06 28 90 01 02 00 06 28 90 01 02 00 2b 28 90 01 02 00 06 26 20 90 01 02 00 00 7e 90 01 02 00 04 7b 90 01 02 00 04 90 00 } //01 00 
		$a_01_1 = {62 65 6c 69 65 76 65 69 6e 74 65 67 72 61 74 65 2e 53 74 75 62 73 } //00 00  believeintegrate.Stubs
	condition:
		any of ($a_*)
 
}