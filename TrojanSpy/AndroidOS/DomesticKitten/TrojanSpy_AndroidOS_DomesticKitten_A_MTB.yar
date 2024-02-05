
rule TrojanSpy_AndroidOS_DomesticKitten_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/DomesticKitten.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 6d 73 6f 62 73 65 72 76 65 72 } //01 00 
		$a_00_1 = {2f 6f 6e 2d 61 6e 73 77 2e 70 68 70 } //01 00 
		$a_00_2 = {2f 6c 67 2d 75 70 6c 64 2e 70 68 70 } //01 00 
		$a_00_3 = {72 64 41 6c 6c 43 6e 74 63 74 73 } //01 00 
		$a_00_4 = {72 64 41 6c 6c 43 61 6c 6c 48 69 73 } //01 00 
		$a_00_5 = {6c 6f 67 42 72 6f 77 73 65 72 } //01 00 
		$a_00_6 = {6c 6f 67 43 6f 6d 6d 61 6e 64 49 6e 66 6f } //01 00 
		$a_00_7 = {2f 66 6c 65 2d 75 70 6c 64 2e 70 68 70 3f 75 75 69 64 3d } //00 00 
	condition:
		any of ($a_*)
 
}