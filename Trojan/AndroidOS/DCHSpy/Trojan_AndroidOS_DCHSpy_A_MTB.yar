
rule Trojan_AndroidOS_DCHSpy_A_MTB{
	meta:
		description = "Trojan:AndroidOS/DCHSpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 6d 61 74 72 69 78 2f 63 74 6f 72 2f 43 61 6d 65 72 61 46 69 6c 65 2f 43 61 6d 65 72 61 46 69 6c 65 } //1 Lcom/matrix/ctor/CameraFile/CameraFile
		$a_01_1 = {4c 63 6f 6d 2f 6d 61 74 72 69 78 2f 63 74 6f 72 2f 57 68 61 74 73 41 70 70 46 69 6c 65 2f 57 68 61 74 73 41 70 70 46 69 6c 65 } //1 Lcom/matrix/ctor/WhatsAppFile/WhatsAppFile
		$a_01_2 = {2f 63 74 6f 72 2f 52 65 63 6f 72 64 69 6e 67 73 46 69 6c 65 2f 52 65 63 6f 72 64 69 6e 67 73 46 69 6c 65 } //1 /ctor/RecordingsFile/RecordingsFile
		$a_01_3 = {2f 64 62 2f 63 6f 6d 6d 61 6e 64 2f 43 6f 6d 6d 61 6e 64 51 75 65 72 69 65 73 } //1 /db/command/CommandQueries
		$a_01_4 = {4c 63 6f 6d 2f 73 66 74 70 5f 75 70 6c 6f 61 64 65 72 2f 74 72 61 76 65 6c 65 72 2f 53 46 54 50 50 72 6f 67 72 65 73 73 4d 6f 6e 69 74 6f 72 } //1 Lcom/sftp_uploader/traveler/SFTPProgressMonitor
		$a_01_5 = {41 63 74 69 6f 6e 44 6f 77 6e 6c 6f 61 64 53 65 72 76 65 72 55 70 64 61 74 65 } //1 ActionDownloadServerUpdate
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}