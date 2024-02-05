
rule Trojan_BAT_Warzone_SK_MTB{
	meta:
		description = "Trojan:BAT/Warzone.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 65 79 73 4e 6f 72 6d 61 6c 69 7a 65 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //01 00 
		$a_01_1 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 73 } //01 00 
		$a_01_2 = {47 4a 51 4a 77 4d 72 51 42 } //01 00 
		$a_01_3 = {4b 65 79 73 4e 6f 72 6d 61 6c 69 7a 65 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}