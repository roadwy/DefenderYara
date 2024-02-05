
rule TrojanSpy_AndroidOS_GPSSpy_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/GPSSpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {54 72 61 63 6b 69 6e 67 20 61 6c 72 65 61 64 79 20 65 6e 61 62 6c 65 64 21 } //01 00 
		$a_00_1 = {67 70 73 70 6f 69 6e 74 73 2f 61 64 64 50 6f 69 6e 74 } //01 00 
		$a_00_2 = {42 6f 6f 74 44 65 74 65 63 74 6f 72 } //01 00 
		$a_00_3 = {2f 73 6d 73 2f 63 6f 6e 74 72 6f 6c 6c 65 72 } //01 00 
		$a_00_4 = {72 6f 75 74 65 63 65 6e 74 72 61 6c 2e 6d 61 78 69 63 6f 6d 2e 6e 65 74 } //00 00 
		$a_00_5 = {5d 04 00 00 } //17 b8 
	condition:
		any of ($a_*)
 
}