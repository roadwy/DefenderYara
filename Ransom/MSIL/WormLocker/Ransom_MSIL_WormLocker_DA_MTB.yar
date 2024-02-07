
rule Ransom_MSIL_WormLocker_DA_MTB{
	meta:
		description = "Ransom:MSIL/WormLocker.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {57 6f 72 6d 4c 6f 63 6b 65 72 32 2e 30 } //01 00  WormLocker2.0
		$a_81_1 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //01 00  DisableTaskMgr
		$a_81_2 = {57 6f 72 6d 5f 70 61 74 63 68 5f 4c 6f 61 64 } //01 00  Worm_patch_Load
		$a_81_3 = {72 61 6e 73 6f 6d 5f 76 6f 69 63 65 2e 76 62 73 } //00 00  ransom_voice.vbs
	condition:
		any of ($a_*)
 
}