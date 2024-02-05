
rule Trojan_BAT_Stimilini_G{
	meta:
		description = "Trojan:BAT/Stimilini.G,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 6f 67 69 6e 5f 44 61 74 61 5f 50 61 74 68 } //01 00 
		$a_00_1 = {47 61 6d 65 73 5c 46 75 63 6b 45 6e 67 69 6e 65 } //01 00 
		$a_00_2 = {5c 53 74 65 61 6d 2e 70 64 62 } //01 00 
		$a_80_3 = {53 74 65 61 6d 20 43 6c 69 65 6e 74 20 42 6f 6f 74 73 74 72 61 70 70 65 72 } //Steam Client Bootstrapper  01 00 
		$a_00_4 = {2e 00 72 00 75 00 2f 00 73 00 74 00 65 00 61 00 6d 00 2f 00 } //00 00 
		$a_00_5 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}