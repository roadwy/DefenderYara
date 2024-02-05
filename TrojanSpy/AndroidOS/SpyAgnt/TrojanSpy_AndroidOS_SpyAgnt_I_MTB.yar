
rule TrojanSpy_AndroidOS_SpyAgnt_I_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SpyAgnt.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 61 70 69 2f 75 70 6c 6f 61 64 73 2f 61 70 69 } //01 00 
		$a_00_1 = {75 70 6c 6f 61 64 43 61 6c 6c 4c 6f 67 } //01 00 
		$a_00_2 = {75 70 6c 6f 61 64 4d 65 73 73 61 67 65 73 } //01 00 
		$a_00_3 = {75 70 6c 6f 61 64 43 6f 6e 74 61 63 74 73 } //01 00 
		$a_00_4 = {75 70 6c 6f 61 64 49 6d 61 67 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}