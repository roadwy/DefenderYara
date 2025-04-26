
rule TrojanSpy_AndroidOS_Fakecall_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Fakecall.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 79 61 6f 77 61 6e 2f 63 6f 64 65 2f 72 65 63 65 69 76 65 72 2f 43 61 6c 6c 4c 6f 67 4f 62 73 65 72 76 65 72 } //1 com/yaowan/code/receiver/CallLogObserver
		$a_00_1 = {43 61 6c 6c 52 65 63 6f 72 64 69 6e 67 44 42 } //1 CallRecordingDB
		$a_00_2 = {64 65 6c 65 74 65 43 61 6c 6c 52 65 63 6f 72 64 69 6e 67 } //1 deleteCallRecording
		$a_00_3 = {55 70 6c 6f 61 64 50 68 6f 6e 65 49 6e 66 6f 52 75 6e 6e 61 62 6c 65 } //1 UploadPhoneInfoRunnable
		$a_01_4 = {45 58 45 43 55 54 45 5f 43 4f 4d 4d 41 4e 44 5f 52 45 43 4f 52 44 49 4e 47 5f 54 49 4d 45 52 5f 44 45 4c 41 59 } //1 EXECUTE_COMMAND_RECORDING_TIMER_DELAY
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}