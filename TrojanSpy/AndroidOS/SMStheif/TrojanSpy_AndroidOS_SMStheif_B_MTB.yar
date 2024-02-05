
rule TrojanSpy_AndroidOS_SMStheif_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SMStheif.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 6b 66 79 74 2e 61 72 68 6b 74 } //01 00 
		$a_00_1 = {31 36 38 78 69 6e 40 31 36 33 2e 63 6f 6d } //01 00 
		$a_00_2 = {67 65 74 54 65 6c 4e 75 6d } //01 00 
		$a_00_3 = {47 65 74 43 6f 6e 74 61 63 74 4c 69 73 74 } //01 00 
		$a_00_4 = {67 65 74 53 6d 73 49 6e 50 68 6f 6e 65 } //01 00 
		$a_00_5 = {64 65 6c 44 78 6e 72 } //01 00 
		$a_00_6 = {73 65 6e 64 64 78 78 78 } //01 00 
		$a_00_7 = {54 68 69 73 20 69 73 20 72 65 62 6f 6f 74 20 66 75 63 6b 69 6e 67 20 79 6f 75 } //00 00 
		$a_00_8 = {5d 04 00 00 cf } //1a 05 
	condition:
		any of ($a_*)
 
}