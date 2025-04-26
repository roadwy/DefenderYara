
rule MonitoringTool_AndroidOS_Prospero_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Prospero.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {52 65 73 65 6e 64 43 6f 6e 74 61 63 74 73 } //1 ResendContacts
		$a_01_1 = {49 6e 63 6f 6d 69 6e 67 53 4d 53 42 61 63 6b 75 70 } //1 IncomingSMSBackup
		$a_01_2 = {4b 69 6c 6c 53 4d 53 42 79 49 44 } //1 KillSMSByID
		$a_01_3 = {70 72 6f 73 70 65 72 6f 2e 70 72 6f 2f 67 70 73 2e 70 68 70 } //1 prospero.pro/gps.php
		$a_01_4 = {4b 69 6c 6c 43 6f 6e 74 61 63 74 73 } //1 KillContacts
		$a_01_5 = {50 72 6f 53 70 65 72 6f 53 65 72 76 69 63 65 } //1 ProSperoService
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}