
rule TrojanSpy_AndroidOS_ProjSpy_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/ProjSpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 65 70 65 61 74 54 61 73 6b 2e 75 70 6c 6f 61 64 46 69 6c 65 73 } //1 RepeatTask.uploadFiles
		$a_01_1 = {50 68 6f 6e 65 4d 6f 6e 69 74 6f 72 } //1 PhoneMonitor
		$a_01_2 = {6e 6f 74 69 66 79 53 65 72 76 65 72 4f 66 43 6f 6d 6d 61 6e 64 45 78 65 63 75 74 69 6f 6e } //1 notifyServerOfCommandExecution
		$a_01_3 = {46 6f 72 63 65 57 69 66 69 4f 6e 46 6f 72 52 65 63 6f 72 64 55 70 6c 6f 61 64 } //1 ForceWifiOnForRecordUpload
		$a_00_4 = {2f 67 65 74 63 6f 6d 6d 61 6e 64 73 2e 70 68 70 } //1 /getcommands.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}