
rule TrojanSpy_AndroidOS_SpyBanker_B{
	meta:
		description = "TrojanSpy:AndroidOS/SpyBanker.B,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 69 6e 64 6f 77 49 6e 53 65 72 76 69 63 65 } //01 00 
		$a_01_1 = {67 65 74 43 61 6c 6c 55 70 64 61 74 65 54 69 6d 65 } //01 00 
		$a_01_2 = {49 4e 3d 43 4f 4d 49 4e 47 5f 43 41 4c 4c } //01 00 
		$a_01_3 = {57 69 6e 64 6f 77 4f 75 74 53 65 72 76 69 63 65 32 } //01 00 
		$a_01_4 = {67 65 74 42 6c 61 63 6b 4c 69 73 74 55 70 64 61 74 65 54 69 6d 65 } //01 00 
		$a_01_5 = {67 65 74 43 68 61 6e 67 65 4e 75 6d 62 65 72 57 68 69 74 65 4c 69 73 74 } //01 00 
		$a_01_6 = {49 4e 43 4f 4d 49 4e 47 5f 43 41 4c 4c 5f 53 54 41 54 45 5f 4f 46 46 48 4f 4f 4b } //00 00 
	condition:
		any of ($a_*)
 
}