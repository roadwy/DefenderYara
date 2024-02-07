
rule TrojanSpy_AndroidOS_Realrat_E_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Realrat.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 74 65 6f 64 6f 72 2e 61 6d 69 72 38 } //01 00  com.teodor.amir8
		$a_00_1 = {50 4e 53 4d 53 } //01 00  PNSMS
		$a_00_2 = {68 69 64 65 41 70 70 49 63 6f 6e } //01 00  hideAppIcon
		$a_00_3 = {75 70 6c 6f 61 64 2e 70 68 70 3f } //01 00  upload.php?
		$a_00_4 = {73 65 6e 64 5f 6c 61 73 74 5f 73 6d 73 } //01 00  send_last_sms
		$a_00_5 = {69 6e 73 74 61 6c 6c 2e 74 78 74 } //01 00  install.txt
		$a_00_6 = {63 6f 6e 74 61 63 74 73 75 74 69 6c 73 } //00 00  contactsutils
	condition:
		any of ($a_*)
 
}