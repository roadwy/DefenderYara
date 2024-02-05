
rule TrojanSpy_AndroidOS_Ahmyth_E_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Ahmyth.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {4c 6a 6f 6b 65 72 2f 6d 69 6e 65 2f 6a 6f 6b 65 72 2f 6a 6f 6b 65 72 2f } //02 00 
		$a_00_1 = {4c 6e 69 63 2f 67 6f 69 2f 61 61 72 6f 67 79 61 73 65 74 75 2f 43 6f 72 6f 6e 61 41 70 70 6c 69 63 61 74 69 6f 6e } //01 00 
		$a_00_2 = {78 6a 6f 6b 65 72 30 31 } //01 00 
		$a_00_3 = {66 6e 5f 68 69 64 65 69 63 6f 6e } //01 00 
		$a_00_4 = {67 65 74 43 61 6c 6c 73 4c 6f 67 73 } //00 00 
		$a_00_5 = {5d 04 00 } //00 5e 
	condition:
		any of ($a_*)
 
}