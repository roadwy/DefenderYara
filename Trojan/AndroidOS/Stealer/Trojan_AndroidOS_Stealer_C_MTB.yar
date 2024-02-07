
rule Trojan_AndroidOS_Stealer_C_MTB{
	meta:
		description = "Trojan:AndroidOS/Stealer.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {72 65 6d 6f 76 65 41 6c 6c 53 6d 73 46 69 6c 74 65 72 73 } //01 00  removeAllSmsFilters
		$a_00_1 = {63 61 74 63 68 53 6d 73 4c 69 73 74 } //01 00  catchSmsList
		$a_00_2 = {73 65 6e 64 43 6f 6e 74 61 63 74 73 54 6f 53 65 72 76 65 72 } //01 00  sendContactsToServer
		$a_00_3 = {4c 73 79 73 74 65 6d 2f 73 65 72 76 69 63 65 2f 53 6d 73 52 65 63 69 76 65 72 } //01 00  Lsystem/service/SmsReciver
		$a_00_4 = {72 65 6d 6f 76 65 41 6c 6c 43 61 74 63 68 46 69 6c 74 65 72 73 } //00 00  removeAllCatchFilters
	condition:
		any of ($a_*)
 
}