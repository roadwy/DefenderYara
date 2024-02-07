
rule TrojanSpy_AndroidOS_Malban_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Malban.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {61 70 70 2f 75 70 64 61 74 65 41 70 70 2e 70 68 70 } //01 00  app/updateApp.php
		$a_00_1 = {73 65 74 44 65 66 61 75 6c 74 53 6d 73 41 70 70 } //01 00  setDefaultSmsApp
		$a_00_2 = {68 61 6e 64 6c 65 49 6e 63 6f 6d 69 6e 67 53 4d 53 } //01 00  handleIncomingSMS
		$a_00_3 = {72 75 6e 2d 73 74 72 49 4d 45 49 3a } //01 00  run-strIMEI:
		$a_00_4 = {63 61 6c 6c 74 72 61 6e 73 66 65 72 72 65 64 6c 69 73 74 } //00 00  calltransferredlist
		$a_00_5 = {5d 04 00 } //00 94 
	condition:
		any of ($a_*)
 
}