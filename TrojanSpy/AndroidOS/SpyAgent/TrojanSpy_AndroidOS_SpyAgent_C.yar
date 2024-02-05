
rule TrojanSpy_AndroidOS_SpyAgent_C{
	meta:
		description = "TrojanSpy:AndroidOS/SpyAgent.C,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 43 61 6c 6c 4c 6f 67 53 65 72 76 69 63 65 3b } //01 00 
		$a_01_1 = {2f 43 68 65 63 6b 52 65 63 6f 72 64 65 72 73 4c 6f 67 53 65 72 76 69 63 65 3b } //01 00 
		$a_01_2 = {65 76 65 72 79 6f 6e 65 2e 65 76 6c } //01 00 
		$a_01_3 = {43 55 52 52 41 4e 54 5f 52 45 43 4f 52 44 5f 50 41 52 54 } //01 00 
		$a_01_4 = {2f 56 69 74 61 6c 53 69 67 6e 73 52 65 63 65 69 76 65 72 3b } //00 00 
		$a_00_5 = {5d 04 00 } //00 08 
	condition:
		any of ($a_*)
 
}