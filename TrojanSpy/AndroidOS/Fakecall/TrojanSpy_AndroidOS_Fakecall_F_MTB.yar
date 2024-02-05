
rule TrojanSpy_AndroidOS_Fakecall_F_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Fakecall.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {75 70 6c 6f 61 64 43 61 6c 6c 4c 6f 67 } //01 00 
		$a_00_1 = {75 70 6c 6f 61 64 52 65 63 6f 72 64 69 6e 67 46 69 6c 65 } //01 00 
		$a_00_2 = {2f 75 73 65 72 2f 75 70 6c 6f 61 64 5f 69 6e 66 6f 5f 66 69 6c 65 } //01 00 
		$a_00_3 = {2f 75 73 65 72 2f 75 70 6c 6f 61 64 5f 72 65 63 6f 72 64 69 6e 67 5f 66 69 6c 65 } //01 00 
		$a_00_4 = {2f 75 73 65 72 2f 75 70 6c 6f 61 64 5f 69 6d 61 67 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}