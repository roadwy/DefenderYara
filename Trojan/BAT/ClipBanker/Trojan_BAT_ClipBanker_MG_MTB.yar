
rule Trojan_BAT_ClipBanker_MG_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {11 08 13 07 7e 01 00 00 04 6f 18 00 00 0a 14 17 8d 01 00 00 01 13 0e 11 0e 16 11 07 a2 11 0e 6f 1c 00 00 0a 26 2b 17 7e 01 00 00 04 6f 18 00 00 0a 14 16 } //01 00 
		$a_01_1 = {43 68 65 63 6b 46 6f 72 49 6e 74 65 72 6e 65 74 43 6f 6e 6e 65 63 74 69 6f 6e } //01 00 
		$a_01_2 = {61 64 64 5f 53 68 75 74 64 6f 77 6e } //01 00 
		$a_01_3 = {47 65 74 41 63 74 69 76 65 50 72 6f 63 65 73 73 46 69 6c 65 4e 61 6d 65 } //00 00 
	condition:
		any of ($a_*)
 
}