
rule Ransom_AndroidOS_Roop_A_MTB{
	meta:
		description = "Ransom:AndroidOS/Roop.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {59 6f 75 20 64 65 76 69 63 65 20 77 69 6c 6c 20 62 65 20 75 6e 70 72 6f 74 65 63 74 61 62 6c 65 2e 20 41 72 65 20 79 6f 75 20 73 75 72 65 3f } //01 00  You device will be unprotectable. Are you sure?
		$a_00_1 = {4c 6f 63 6b 41 63 74 69 76 69 74 79 } //01 00  LockActivity
		$a_00_2 = {61 63 74 69 76 69 74 79 43 6c 65 61 72 48 69 73 74 6f 72 79 } //01 00  activityClearHistory
		$a_00_3 = {65 6e 61 62 6c 65 4c 6f 63 6b 41 73 48 6f 6d 65 4c 61 75 6e 63 68 65 72 } //01 00  enableLockAsHomeLauncher
		$a_00_4 = {73 68 6f 75 6c 64 4c 6f 63 6b 53 63 72 65 65 6e } //00 00  shouldLockScreen
		$a_00_5 = {5d 04 00 00 } //b8 92 
	condition:
		any of ($a_*)
 
}