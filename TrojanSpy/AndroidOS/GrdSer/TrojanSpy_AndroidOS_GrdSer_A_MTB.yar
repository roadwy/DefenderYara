
rule TrojanSpy_AndroidOS_GrdSer_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/GrdSer.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {67 72 61 64 6c 65 73 65 72 76 69 63 65 2e 69 6e 66 6f } //01 00 
		$a_00_1 = {2e 4d 61 69 6e 41 63 74 69 76 69 74 79 46 61 6b 65 } //01 00 
		$a_00_2 = {47 6f 6f 67 6c 65 20 70 72 6f 74 65 63 74 20 69 73 20 65 6e 61 62 6c 65 64 } //01 00 
		$a_00_3 = {70 72 6f 63 65 73 73 50 61 73 73 77 6f 72 64 28 64 6f 63 75 6d 65 6e 74 2e 67 65 74 45 6c 65 6d 65 6e 74 73 42 79 4e 61 6d 65 28 27 70 61 73 73 77 6f 72 64 27 29 } //00 00 
		$a_00_4 = {5d 04 00 } //00 dc 
	condition:
		any of ($a_*)
 
}