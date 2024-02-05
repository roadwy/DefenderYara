
rule TrojanSpy_AndroidOS_laucassSpy_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/laucassSpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {72 65 6d 6f 74 65 5f 72 65 63 6f 72 64 } //01 00 
		$a_00_1 = {63 6f 6d 2e 6c 61 75 63 61 73 73 2e 61 6e 64 72 6f 73 6d 73 63 6f 6e 74 72 6f 6c } //01 00 
		$a_00_2 = {68 69 64 65 5f 6b 65 79 77 6f 72 64 5f 73 6d 73 } //01 00 
		$a_00_3 = {50 68 6f 6e 65 43 6f 6e 74 72 6f 6c 44 65 76 69 63 65 41 64 6d 69 6e 52 65 63 65 69 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}