
rule TrojanSpy_AndroidOS_FakeInst_T_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FakeInst.T!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 69 70 72 6f 67 5f 43 6c 69 63 6b } //01 00  biprog_Click
		$a_01_1 = {75 6e 63 72 79 70 74 65 64 48 65 6c 6c 6f 57 6f 72 6c 64 33 } //01 00  uncryptedHelloWorld3
		$a_01_2 = {62 72 75 6c 65 73 5f 43 6c 69 63 6b } //01 00  brules_Click
		$a_01_3 = {63 6f 6d 2f 44 6f 6f 64 6c 65 5f 50 68 79 73 69 63 73 2f 67 61 6d 65 } //00 00  com/Doodle_Physics/game
	condition:
		any of ($a_*)
 
}