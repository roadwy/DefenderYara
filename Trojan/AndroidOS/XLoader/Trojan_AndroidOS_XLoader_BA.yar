
rule Trojan_AndroidOS_XLoader_BA{
	meta:
		description = "Trojan:AndroidOS/XLoader.BA,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 32 56 30 51 32 39 74 63 47 39 75 5a 57 35 30 52 57 35 68 59 6d 78 6c 5a 46 4e 6c 64 48 52 70 62 6d 63 3d } //01 00 
		$a_01_1 = {4d 45 54 41 53 50 4c 4f 49 54 } //01 00 
		$a_01_2 = {2e 4c 6f 61 64 65 72 } //01 00 
		$a_01_3 = {61 6e 64 72 6f 69 64 2e 69 6e 74 65 6e 74 2e 61 63 74 69 6f 6e 2e 42 4f 4f 54 5f 43 4f 4d 50 4c 45 54 45 44 } //00 00 
	condition:
		any of ($a_*)
 
}