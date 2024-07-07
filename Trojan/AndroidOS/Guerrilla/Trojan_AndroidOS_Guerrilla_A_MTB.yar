
rule Trojan_AndroidOS_Guerrilla_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Guerrilla.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_00_0 = {6e 75 6d 62 65 72 49 6e 43 6f 6e 74 72 61 63 74 } //1 numberInContract
		$a_00_1 = {67 65 74 53 6d 73 43 6f 75 6e 74 } //1 getSmsCount
		$a_00_2 = {63 61 6e 4b 69 6c 6c 50 68 6f 6e 65 50 72 6f 63 65 73 73 } //1 canKillPhoneProcess
		$a_00_3 = {53 6d 73 48 6f 6f 6b } //1 SmsHook
		$a_00_4 = {64 65 6c 53 65 6e 64 4d 73 67 } //1 delSendMsg
		$a_00_5 = {73 6d 5f 73 70 5f 77 73 5f 75 72 6c } //1 sm_sp_ws_url
		$a_00_6 = {68 6f 6f 6b 50 68 6f 6e 65 } //1 hookPhone
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}
rule Trojan_AndroidOS_Guerrilla_A_MTB_2{
	meta:
		description = "Trojan:AndroidOS/Guerrilla.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_00_0 = {73 65 74 50 72 65 6d 69 75 6d 53 6d 73 50 65 72 6d 69 73 73 69 6f 6e } //1 setPremiumSmsPermission
		$a_00_1 = {7a 68 2e 79 6f 6d 6f 62 69 2e 6e 65 74 3a 38 30 38 30 } //1 zh.yomobi.net:8080
		$a_00_2 = {70 61 75 73 65 44 6f 77 6e 6c 6f 61 64 41 64 73 } //1 pauseDownloadAds
		$a_00_3 = {73 65 6e 64 4d 65 73 73 61 67 65 } //1 sendMessage
		$a_00_4 = {7a 68 5f 6f 74 61 2e 6c 6f 67 } //1 zh_ota.log
		$a_00_5 = {63 6f 6d 2e 61 6e 64 72 6f 69 64 2e 67 6f 6f 62 72 77 2e 73 64 6b 2e 63 6f 6d 70 72 65 73 73 2e 68 65 6c 70 72 65 63 65 69 76 65 72 2e 48 65 6c 70 58 52 65 63 65 69 76 65 72 } //2 com.android.goobrw.sdk.compress.helpreceiver.HelpXReceiver
		$a_00_6 = {41 64 4d 61 6e 61 67 65 72 2e 6a 61 76 61 } //1 AdManager.java
		$a_00_7 = {61 6e 64 72 6f 69 64 2e 69 6e 74 65 6e 74 2e 61 63 74 69 6f 6e 2e 42 4f 4f 54 5f 43 4f 4d 50 4c 45 54 45 44 } //1 android.intent.action.BOOT_COMPLETED
		$a_00_8 = {67 61 6d 65 73 2e 61 6e 64 72 6f 69 64 61 64 2e 6e 65 74 3a 39 30 38 30 2f 75 70 6c 6f 61 64 2f 6a 61 72 2f 66 36 2e 6a 61 72 20 } //1 games.androidad.net:9080/upload/jar/f6.jar 
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*2+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=7
 
}