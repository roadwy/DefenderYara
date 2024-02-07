
rule TrojanSpy_AndroidOS_ServcRAT_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/ServcRAT.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {4c 63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 72 65 76 65 72 73 65 73 68 65 6c 6c 90 02 03 2f 50 61 79 6c 6f 61 64 73 2f 6e 65 77 53 68 65 6c 6c 90 00 } //01 00 
		$a_00_1 = {68 69 64 65 41 70 70 49 63 6f 6e } //01 00  hideAppIcon
		$a_00_2 = {67 65 74 50 68 6f 6e 65 4e 75 6d 62 65 72 } //01 00  getPhoneNumber
		$a_00_3 = {67 65 74 5f 6e 75 6d 62 65 72 4f 66 43 61 6d 65 72 61 73 } //01 00  get_numberOfCameras
		$a_00_4 = {67 65 74 43 61 6c 6c 4c 6f 67 73 } //01 00  getCallLogs
		$a_00_5 = {67 65 74 53 4d 53 } //00 00  getSMS
	condition:
		any of ($a_*)
 
}