
rule Trojan_BAT_LimeRat_SBR_MSR{
	meta:
		description = "Trojan:BAT/LimeRat.SBR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 67 69 74 68 75 62 2e 63 6f 6d 2f 4c 69 6d 65 72 42 6f 79 2f 53 74 6f 72 6d 4b 69 74 74 79 } //01 00 
		$a_01_1 = {67 65 74 5f 54 61 72 67 65 74 } //01 00 
		$a_01_2 = {44 65 63 6f 64 65 44 69 72 65 63 74 42 69 74 73 } //01 00 
		$a_01_3 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //00 00 
	condition:
		any of ($a_*)
 
}