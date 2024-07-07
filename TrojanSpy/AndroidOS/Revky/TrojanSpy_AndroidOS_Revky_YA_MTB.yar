
rule TrojanSpy_AndroidOS_Revky_YA_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Revky.YA!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 07 00 00 "
		
	strings :
		$a_00_0 = {72 65 76 2f 6b 65 79 6c 6f 67 2f 6c 6f 67 73 2e 73 65 72 } //1 rev/keylog/logs.ser
		$a_00_1 = {6e 6f 74 69 66 69 63 61 74 69 6f 6e 73 2f 6e 6f 74 69 66 69 63 61 74 69 6f 6e 73 2e 73 65 72 } //1 notifications/notifications.ser
		$a_00_2 = {72 65 76 2f 73 63 72 65 65 6e 73 68 6f 74 73 } //1 rev/screenshots
		$a_00_3 = {73 79 73 74 65 6d 2f 62 69 6e 2f 73 63 72 65 65 6e 63 61 70 20 2d 70 } //1 system/bin/screencap -p
		$a_00_4 = {72 65 76 63 6f 64 65 2f 73 63 72 65 65 6e 73 68 6f 74 73 } //1 revcode/screenshots
		$a_00_5 = {72 65 76 63 6f 64 65 2f 72 65 63 6f 72 64 69 6e 67 73 } //1 revcode/recordings
		$a_80_6 = {52 65 63 6f 72 64 43 61 6c 6c 73 53 65 72 76 69 63 65 20 53 54 41 54 45 5f 53 54 41 52 54 5f 52 45 43 4f 52 44 49 4e 47 } //RecordCallsService STATE_START_RECORDING  1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_80_6  & 1)*1) >=4
 
}