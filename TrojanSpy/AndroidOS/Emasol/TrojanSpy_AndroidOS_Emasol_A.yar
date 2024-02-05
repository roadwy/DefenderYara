
rule TrojanSpy_AndroidOS_Emasol_A{
	meta:
		description = "TrojanSpy:AndroidOS/Emasol.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 6e 64 72 6f 69 64 5f 61 73 73 65 74 2f 69 6e 64 65 78 2e 68 74 6d 6c } //01 00 
		$a_01_1 = {61 70 70 2d 72 6f 69 64 2e 63 6f 6d 2f 61 70 70 2f 72 76 2e 70 68 70 3f 69 64 3d } //01 00 
		$a_01_2 = {6d 61 69 6c 61 64 64 72 65 73 73 20 67 65 74 21 } //00 00 
	condition:
		any of ($a_*)
 
}