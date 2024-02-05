
rule TrojanSpy_AndroidOS_Ahmyth_I_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Ahmyth.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 74 65 63 68 65 78 70 65 72 74 2f 73 70 61 63 65 6d 65 73 73 61 6e 67 65 72 2f 73 65 72 76 69 63 65 73 } //02 00 
		$a_00_1 = {33 2e 74 63 70 2e 6e 67 72 6f 6b 2e 69 6f } //01 00 
		$a_00_2 = {63 6f 6e 74 61 63 74 73 4c 69 73 74 } //01 00 
		$a_00_3 = {26 6d 61 6e 66 3d } //01 00 
		$a_00_4 = {4d 61 6c 66 6f 72 6d 65 64 20 63 6c 6f 73 65 20 70 61 79 6c 6f 61 64 } //00 00 
	condition:
		any of ($a_*)
 
}