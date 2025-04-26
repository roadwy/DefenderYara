
rule TrojanSpy_AndroidOS_InfoStealer_GK_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/InfoStealer.GK!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 74 65 73 74 2e 61 63 63 65 73 73 69 62 69 6c 69 74 79 2e 4d 79 41 63 63 65 73 73 69 62 69 6c 69 74 79 53 65 72 76 69 63 65 } //1 com.test.accessibility.MyAccessibilityService
		$a_00_1 = {63 72 79 70 74 6f 2e 74 72 75 73 74 61 70 70 2e 75 69 2e 77 61 6c 6c 65 74 73 2e 61 63 74 69 76 69 74 79 2e 45 78 70 6f 72 74 50 68 72 61 73 65 41 63 74 69 76 69 74 79 } //1 crypto.trustapp.ui.wallets.activity.ExportPhraseActivity
		$a_01_2 = {70 65 72 66 6f 72 6d 47 6c 6f 62 61 6c 41 63 74 69 6f 6e } //1 performGlobalAction
		$a_02_3 = {68 74 74 70 3a 2f 2f [0-20] 2f 61 70 69 2f 72 65 73 74 2f } //1
		$a_00_4 = {61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 } //1 api.telegram.org/bot
		$a_00_5 = {6d 6f 6e 69 74 6f 72 20 79 6f 75 72 20 61 63 74 69 76 69 74 79 } //1 monitor your activity
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}