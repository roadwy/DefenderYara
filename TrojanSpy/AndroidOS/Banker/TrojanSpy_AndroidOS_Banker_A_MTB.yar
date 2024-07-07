
rule TrojanSpy_AndroidOS_Banker_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_00_0 = {41 6e 64 72 6f 69 64 42 6f 74 2f 53 63 72 65 65 6e 63 61 73 74 } //3 AndroidBot/Screencast
		$a_00_1 = {61 6e 64 72 6f 69 64 3a 69 64 2f 73 6d 73 5f 73 68 6f 72 74 5f 63 6f 64 65 5f 72 65 6d 65 6d 62 65 72 5f 63 68 6f 69 63 65 5f 63 68 65 63 6b 62 6f 78 } //3 android:id/sms_short_code_remember_choice_checkbox
		$a_00_2 = {74 74 39 2e 70 61 67 65 2e 6c 69 6e 6b 2f 58 6b 74 53 } //1 tt9.page.link/XktS
		$a_00_3 = {49 6e 6a 65 63 74 43 6f 6d 70 6f 6e 65 6e 74 } //1 InjectComponent
		$a_00_4 = {72 65 71 75 65 73 74 5f 63 72 65 64 65 6e 74 69 61 6c 73 } //1 request_credentials
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*3+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=7
 
}
rule TrojanSpy_AndroidOS_Banker_A_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6f 6d 68 61 63 68 74 61 69 67 68 3a 3a 5b 69 73 5d 76 69 72 6b 6a 61 3a 3a 5b 65 73 5d 61 63 74 69 76 61 72 3a 3a 5b 69 74 5d 61 74 74 69 76 61 72 65 3a 3a 5b 6b 6b 5d } //1 omhachtaigh::[is]virkja::[es]activar::[it]attivare::[kk]
		$a_00_1 = {41 43 43 3a 3a 6f 6e 41 63 63 65 73 73 69 62 69 6c 69 74 79 45 76 65 6e 74 3a 20 6c 65 66 74 5f 62 75 74 74 6f 6e } //1 ACC::onAccessibilityEvent: left_button
		$a_00_2 = {41 63 63 65 73 73 3d 31 50 65 72 6d 3d 31 } //1 Access=1Perm=1
		$a_00_3 = {43 63 6f 6d 2e 67 6f 6f 67 6c 65 2e 61 6e 64 72 6f 69 64 2e 67 6d 73 2e 73 65 63 75 72 69 74 79 2e 73 65 74 74 69 6e 67 73 2e 56 65 72 69 66 79 41 70 70 73 53 65 74 74 69 6e 67 73 41 63 74 69 76 69 74 79 } //1 Ccom.google.android.gms.security.settings.VerifyAppsSettingsActivity
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}