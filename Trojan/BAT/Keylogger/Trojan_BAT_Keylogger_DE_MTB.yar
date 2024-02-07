
rule Trojan_BAT_Keylogger_DE_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {47 65 74 4f 75 74 6c 6f 6f 6b 50 61 73 73 77 6f 72 64 73 } //01 00  GetOutlookPasswords
		$a_81_1 = {47 65 74 4b 65 79 6c 6f 67 67 65 72 44 61 74 61 } //01 00  GetKeyloggerData
		$a_81_2 = {44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 } //01 00  DisableRegistryTools
		$a_81_3 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //01 00  DisableTaskMgr
		$a_81_4 = {55 70 6c 6f 61 64 44 61 74 61 } //01 00  UploadData
		$a_81_5 = {74 68 65 6b 65 79 64 61 74 61 2e 6c 6f 67 } //00 00  thekeydata.log
	condition:
		any of ($a_*)
 
}