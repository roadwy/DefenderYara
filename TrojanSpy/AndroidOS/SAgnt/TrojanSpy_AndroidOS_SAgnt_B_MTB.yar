
rule TrojanSpy_AndroidOS_SAgnt_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_02_0 = {2f 73 6d 73 90 01 04 2e 70 68 70 3f 75 70 6c 6f 61 64 73 6d 73 3d 90 00 } //01 00 
		$a_00_1 = {55 70 6c 6f 61 64 46 69 6c 65 50 68 70 } //01 00 
		$a_00_2 = {2f 53 6d 73 2e 74 78 74 } //01 00 
		$a_00_3 = {55 70 6c 6f 61 64 4b 69 6c 6c } //00 00 
		$a_00_4 = {5d 04 00 } //00 f5 
	condition:
		any of ($a_*)
 
}