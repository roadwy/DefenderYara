
rule TrojanSpy_AndroidOS_InfoStealer_K_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/InfoStealer.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 6e 65 74 2f 61 78 65 6c 2f 61 70 70 2f 73 65 72 73 65 73 2f } //01 00  Lnet/axel/app/serses/
		$a_00_1 = {69 6e 73 74 61 6c 6c 5f 6e 6f 6e 5f 6d 61 72 6b 65 74 5f 61 70 70 73 } //01 00  install_non_market_apps
		$a_00_2 = {53 4d 53 5f 52 65 63 63 6f 72 64 69 6e 67 } //01 00  SMS_Reccording
		$a_00_3 = {63 6f 6d 2e 61 6e 64 72 6f 69 64 2e 73 65 74 74 69 6e 67 73 3a 69 64 2f 6c 65 66 74 5f 62 75 74 74 6f 6e } //01 00  com.android.settings:id/left_button
		$a_00_4 = {4f 55 54 47 4f 49 4e 47 5f 57 48 41 54 53 41 50 50 5f 43 41 4c 4c } //00 00  OUTGOING_WHATSAPP_CALL
		$a_00_5 = {5d 04 00 00 } //84 6d 
	condition:
		any of ($a_*)
 
}