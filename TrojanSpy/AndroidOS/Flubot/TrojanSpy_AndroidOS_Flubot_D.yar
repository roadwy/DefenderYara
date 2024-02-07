
rule TrojanSpy_AndroidOS_Flubot_D{
	meta:
		description = "TrojanSpy:AndroidOS/Flubot.D,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 6d 69 44 65 66 61 75 6c 74 53 6d 73 } //01 00  AmiDefaultSms
		$a_01_1 = {41 75 74 6f 41 63 63 65 70 74 50 65 72 6d 73 } //01 00  AutoAcceptPerms
		$a_00_2 = {43 4f 4e 54 41 43 54 5f 54 41 42 5f 50 4f 53 } //01 00  CONTACT_TAB_POS
		$a_01_3 = {47 65 74 43 6f 6e 74 61 63 74 4c 69 73 74 55 70 6c 6f 61 64 } //00 00  GetContactListUpload
	condition:
		any of ($a_*)
 
}