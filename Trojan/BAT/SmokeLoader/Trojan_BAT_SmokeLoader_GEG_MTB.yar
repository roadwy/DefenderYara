
rule Trojan_BAT_SmokeLoader_GEG_MTB{
	meta:
		description = "Trojan:BAT/SmokeLoader.GEG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 32 46 70 64 45 5a 76 63 6c 4e 70 62 6d 64 73 5a 55 39 69 61 6d 56 6a 64 41 3d 3d } //01 00 
		$a_01_1 = {58 7a 41 77 4e 31 4e 30 64 57 49 75 55 48 4a 76 63 47 56 79 64 47 6c 6c 63 79 35 53 5a 58 4e 76 64 58 4a 6a 5a 58 4d 3d } //01 00 
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //01 00 
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00 
	condition:
		any of ($a_*)
 
}