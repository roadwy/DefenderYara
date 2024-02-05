
rule TrojanSpy_BAT_Omaneat_C{
	meta:
		description = "TrojanSpy:BAT/Omaneat.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3c 48 6f 73 74 3e 28 2e 2b 3f 29 3c 2f 48 6f 73 74 3e 5c 73 2b 2e 2b 5c 73 2b 2e 2b 5c 73 2b 2e 2b 5c 73 2b 3c 55 73 65 72 3e 28 2e 2b 3f 29 3c 2f 55 73 65 72 3e 5c 73 2b 3c 50 61 73 73 3e 28 2e 2b 3f 29 3c 2f 50 61 73 73 3e } //01 00 
		$a_01_1 = {53 54 4f 50 44 44 4f 53 } //01 00 
		$a_01_2 = {53 54 41 52 54 43 41 4d } //01 00 
		$a_01_3 = {4c 75 6d 69 6e 6f 73 69 74 79 43 72 79 70 74 6f 4d 69 6e 65 72 } //00 00 
		$a_00_4 = {7e 15 } //00 00 
	condition:
		any of ($a_*)
 
}