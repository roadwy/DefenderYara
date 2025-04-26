
rule MonitoringTool_AndroidOS_Atmt_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Atmt.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 61 74 6d 74 68 75 62 2f 61 74 6d 74 70 72 6f 2f 63 6f 6d 6d 6f 6e 5f 6d 6f 64 65 6c 2f 42 61 63 6b 75 70 41 63 74 69 76 69 74 79 } //1 Lcom/atmthub/atmtpro/common_model/BackupActivity
		$a_00_1 = {4c 63 6f 6d 2f 61 74 6d 74 68 75 62 2f 61 74 6d 74 70 72 6f 2f 72 65 63 65 69 76 65 72 5f 6d 6f 64 65 6c 2f 73 6d 73 2f 53 4d 53 72 65 63 65 69 76 65 72 } //1 Lcom/atmthub/atmtpro/receiver_model/sms/SMSreceiver
		$a_00_2 = {4c 6f 63 61 74 69 6f 6e 54 72 61 63 6b 69 6e 67 53 65 72 76 69 63 65 } //1 LocationTrackingService
		$a_00_3 = {50 64 66 46 69 6c 65 54 6f 53 65 6e 64 2e 70 64 66 } //1 PdfFileToSend.pdf
		$a_00_4 = {6c 69 73 74 63 61 6c 6c 53 74 72 69 6e 67 } //1 listcallString
		$a_00_5 = {6c 69 73 74 63 61 6c 6c 6c 6f 67 53 74 72 69 6e 67 } //1 listcalllogString
		$a_00_6 = {6c 69 73 74 6d 65 73 61 67 65 53 74 72 69 6e 67 } //1 listmesageString
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}