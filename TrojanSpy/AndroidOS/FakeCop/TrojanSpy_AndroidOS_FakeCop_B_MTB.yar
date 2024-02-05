
rule TrojanSpy_AndroidOS_FakeCop_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FakeCop.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 72 74 41 70 70 6c 69 63 61 74 69 6f 6e } //01 00 
		$a_01_1 = {52 35 35 52 65 63 65 69 76 65 72 } //01 00 
		$a_01_2 = {6c 6f 61 64 4c 69 62 72 61 72 79 } //01 00 
		$a_00_3 = {6f 10 04 00 01 00 6e 10 03 00 01 00 0c 00 71 20 16 00 01 00 0e 00 } //00 00 
	condition:
		any of ($a_*)
 
}