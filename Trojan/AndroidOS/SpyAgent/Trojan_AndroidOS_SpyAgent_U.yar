
rule Trojan_AndroidOS_SpyAgent_U{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.U,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 65 73 68 69 20 65 6e 74 65 72 20 6d 61 69 6e 32 32 32 } //01 00  ceshi enter main222
		$a_01_1 = {63 65 73 68 69 20 65 6e 74 65 72 20 68 6f 6d 65 } //00 00  ceshi enter home
	condition:
		any of ($a_*)
 
}
rule Trojan_AndroidOS_SpyAgent_U_2{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.U,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {47 45 54 5f 4c 41 53 54 5f 53 4d 53 5f 49 4e 42 4f 58 } //02 00  GET_LAST_SMS_INBOX
		$a_01_1 = {4e 4f 5f 53 49 4c 45 4e 54 5f 53 4d 53 } //02 00  NO_SILENT_SMS
		$a_01_2 = {47 45 54 5f 41 4c 4c 5f 53 4d 53 5f 53 45 4e 54 } //00 00  GET_ALL_SMS_SENT
	condition:
		any of ($a_*)
 
}