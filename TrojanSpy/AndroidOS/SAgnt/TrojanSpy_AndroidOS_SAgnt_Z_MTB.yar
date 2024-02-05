
rule TrojanSpy_AndroidOS_SAgnt_Z_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.Z!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 70 6c 6f 61 64 50 68 6f 6e 65 53 65 72 76 69 63 65 } //01 00 
		$a_01_1 = {2f 77 65 62 2f 6c 2e 61 73 70 78 3f 70 68 6f 6e 65 3d } //01 00 
		$a_01_2 = {48 69 64 65 49 63 6f 6e } //01 00 
		$a_01_3 = {67 65 74 53 65 6e 64 53 4d 53 49 6e 66 6f } //01 00 
		$a_01_4 = {6a 75 64 67 65 49 73 53 65 6e 64 65 64 } //00 00 
	condition:
		any of ($a_*)
 
}