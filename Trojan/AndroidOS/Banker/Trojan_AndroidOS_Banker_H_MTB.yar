
rule Trojan_AndroidOS_Banker_H_MTB{
	meta:
		description = "Trojan:AndroidOS/Banker.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 65 6e 64 4c 6f 67 73 4b 65 79 6c 6f 67 67 65 72 } //01 00  sendLogsKeylogger
		$a_00_1 = {6c 6f 67 73 43 6f 6e 74 61 63 74 73 } //01 00  logsContacts
		$a_00_2 = {73 65 6e 64 4c 6f 67 73 53 4d 53 } //01 00  sendLogsSMS
		$a_00_3 = {73 77 61 70 53 6d 73 4d 65 6e 61 67 65 72 } //00 00  swapSmsMenager
	condition:
		any of ($a_*)
 
}