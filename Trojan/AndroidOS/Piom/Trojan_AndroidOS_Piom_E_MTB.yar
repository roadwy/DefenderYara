
rule Trojan_AndroidOS_Piom_E_MTB{
	meta:
		description = "Trojan:AndroidOS/Piom.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 61 76 65 74 61 72 67 65 74 64 65 76 69 63 65 69 6e 66 6f 2e 70 68 70 } //01 00  savetargetdeviceinfo.php
		$a_00_1 = {43 72 65 61 74 65 44 62 54 6f 5a 69 70 41 6e 64 53 65 6e 64 54 6f } //01 00  CreateDbToZipAndSendTo
		$a_00_2 = {64 62 62 61 63 6b 75 70 2e 7a 69 70 } //01 00  dbbackup.zip
		$a_00_3 = {73 61 76 65 5f 62 72 6f 77 73 69 6e 67 5f 68 69 73 74 6f 72 79 2e 70 68 70 } //01 00  save_browsing_history.php
		$a_00_4 = {63 61 6c 6c 4c 6f 67 2e 64 62 } //01 00  callLog.db
		$a_00_5 = {67 65 74 54 61 72 67 65 74 44 61 74 61 62 61 73 65 2e 70 68 70 } //00 00  getTargetDatabase.php
	condition:
		any of ($a_*)
 
}