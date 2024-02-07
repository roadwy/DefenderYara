
rule Trojan_BAT_Nanocore_NAC_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.NAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {13 08 7e 55 00 00 04 11 05 20 90 01 03 00 58 61 80 90 01 03 04 11 08 2c 0e 7e 90 01 03 04 11 08 28 90 01 03 06 2b 01 90 00 } //01 00 
		$a_01_1 = {61 64 64 5f 52 65 73 6f 75 72 63 65 52 65 73 6f 6c 76 65 } //01 00  add_ResourceResolve
		$a_01_2 = {50 72 6f 63 65 73 73 57 69 6e 64 6f 77 53 74 79 6c 65 } //00 00  ProcessWindowStyle
	condition:
		any of ($a_*)
 
}