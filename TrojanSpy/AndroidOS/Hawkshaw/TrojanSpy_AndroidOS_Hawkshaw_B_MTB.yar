
rule TrojanSpy_AndroidOS_Hawkshaw_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Hawkshaw.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_00_0 = {68 61 77 6b 73 68 61 77 2e 74 61 73 6b 73 2e 6d 65 64 69 61 2e 53 63 72 65 65 6e 52 65 63 6f 72 64 } //1 hawkshaw.tasks.media.ScreenRecord
		$a_00_1 = {2f 61 70 70 2f 68 69 64 64 65 6e } //1 /app/hidden
		$a_00_2 = {2f 6b 65 79 6c 6f 67 67 65 72 2f 6b 65 79 6c 6f 67 67 65 72 2f } //1 /keylogger/keylogger/
		$a_00_3 = {6d 65 2e 68 61 77 6b 73 68 61 77 2e 72 65 63 65 69 76 65 72 } //1 me.hawkshaw.receiver
		$a_00_4 = {64 65 6c 65 74 65 41 6c 6c 44 6f 77 6e 6c 6f 61 64 54 6f 4c 6f 63 61 6c 54 61 73 6b 73 } //1 deleteAllDownloadToLocalTasks
		$a_00_5 = {64 65 76 69 63 65 2d 69 6e 66 6f 20 75 70 6c 6f 61 64 20 73 75 63 63 65 73 73 66 75 6c } //1 device-info upload successful
		$a_00_6 = {6d 65 2e 68 61 77 6b 73 68 61 77 2e 6d 6f 64 65 6c 2e 55 70 6c 6f 61 64 54 61 73 6b 3b } //1 me.hawkshaw.model.UploadTask;
		$a_00_7 = {6d 65 2e 68 61 77 6b 73 68 61 77 2e 74 61 73 6b 73 2e 4c 6f 63 61 74 69 6f 6e 4d 6f 6e 69 74 6f 72 46 75 73 65 64 } //1 me.hawkshaw.tasks.LocationMonitorFused
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=7
 
}