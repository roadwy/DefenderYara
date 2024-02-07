
rule Adware_AndroidOS_Vuad_D_MTB{
	meta:
		description = "Adware:AndroidOS/Vuad.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6d 2f 72 6c 74 65 63 68 2f 67 6c 6f 62 61 6c } //01 00  cm/rltech/global
		$a_00_1 = {69 6e 73 74 61 6c 6c 41 70 70 } //01 00  installApp
		$a_00_2 = {67 65 74 50 68 6f 6e 65 44 61 74 61 } //01 00  getPhoneData
		$a_00_3 = {67 65 74 69 70 61 64 64 72 65 73 73 } //01 00  getipaddress
		$a_00_4 = {67 65 74 50 68 6f 6e 65 43 61 6c 6c 4c 6f 67 } //01 00  getPhoneCallLog
		$a_00_5 = {67 65 74 43 6f 6e 74 61 63 74 4c 69 73 74 } //01 00  getContactList
		$a_00_6 = {4c 6f 63 6b 42 6f 6f 74 43 6f 6d 70 6c 65 74 65 52 65 63 65 69 76 65 72 } //00 00  LockBootCompleteReceiver
	condition:
		any of ($a_*)
 
}