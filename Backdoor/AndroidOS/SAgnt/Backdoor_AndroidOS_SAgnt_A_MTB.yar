
rule Backdoor_AndroidOS_SAgnt_A_MTB{
	meta:
		description = "Backdoor:AndroidOS/SAgnt.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {2f 6e 6f 74 69 66 69 63 61 74 69 6f 6e 5f 64 69 73 61 62 6c 65 2e 70 68 70 } //1 /notification_disable.php
		$a_01_1 = {2f 61 70 69 2f 43 61 6c 6c 4c 6f 67 } //1 /api/CallLog
		$a_01_2 = {2f 61 70 69 2f 55 70 6c 6f 61 64 44 69 72 65 63 74 6f 72 79 } //1 /api/UploadDirectory
		$a_01_3 = {52 65 61 64 20 4b 65 79 6c 6f 67 65 72 } //1 Read Keyloger
		$a_00_4 = {4c 63 6f 6d 2f 61 68 72 61 72 2f 6d 65 64 69 61 } //1 Lcom/ahrar/media
		$a_01_5 = {4b 65 79 6c 6f 67 65 72 53 65 6e 64 53 74 61 74 75 73 } //1 KeylogerSendStatus
		$a_01_6 = {53 65 6e 64 46 69 6c 65 53 65 72 76 65 72 } //1 SendFileServer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}