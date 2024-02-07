
rule TrojanSpy_AndroidOS_Spynote_I_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Spynote.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 61 63 6b 4d 65 55 70 4a 6f 62 } //01 00  WackMeUpJob
		$a_01_1 = {69 73 53 65 72 76 69 63 65 57 6f 72 6b } //01 00  isServiceWork
		$a_01_2 = {61 63 74 69 76 69 74 79 61 64 6d } //01 00  activityadm
		$a_01_3 = {70 68 6f 6e 69 78 65 66 66 65 63 74 } //00 00  phonixeffect
	condition:
		any of ($a_*)
 
}