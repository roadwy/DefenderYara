
rule TrojanSpy_AndroidOS_Campys_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Campys.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 03 00 "
		
	strings :
		$a_00_0 = {3a 2f 2f 77 77 77 2e 66 69 72 6d 77 61 72 65 73 79 73 74 65 6d 75 70 64 61 74 65 2e 63 6f 6d 2f 68 61 73 73 } //01 00  ://www.firmwaresystemupdate.com/hass
		$a_00_1 = {42 41 43 4b 47 52 4f 55 4e 44 5f 54 48 52 45 41 44 5f 4b 45 45 50 5f 41 4c 49 56 45 5f 44 55 52 41 54 49 4f 4e 5f 4d 53 } //02 00  BACKGROUND_THREAD_KEEP_ALIVE_DURATION_MS
		$a_00_2 = {75 70 6c 6f 61 64 2d 66 69 6c 65 2e 70 68 70 3f 75 75 69 64 } //01 00  upload-file.php?uuid
		$a_00_3 = {61 6e 73 77 65 72 2e 70 68 70 } //01 00  answer.php
		$a_00_4 = {52 65 63 6f 72 64 20 43 61 6c 6c } //00 00  Record Call
		$a_00_5 = {5d 04 00 00 } //e4 64 
	condition:
		any of ($a_*)
 
}