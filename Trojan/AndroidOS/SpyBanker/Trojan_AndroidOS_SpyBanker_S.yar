
rule Trojan_AndroidOS_SpyBanker_S{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.S,SIGNATURE_TYPE_DEXHSTR_EXT,0a 00 0a 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {48 65 6c 6c 6f 74 65 61 63 68 65 72 53 65 72 76 69 63 65 } //02 00  HelloteacherService
		$a_01_1 = {69 73 52 65 71 50 65 72 6d 69 73 73 69 6f 6e } //02 00  isReqPermission
		$a_01_2 = {75 6e 6c 6f 63 6b 5f 73 63 72 65 65 6e 5f 67 65 73 74 75 72 65 73 } //02 00  unlock_screen_gestures
		$a_01_3 = {73 63 72 65 65 6e 5f 6d 75 6c 74 69 5f 74 61 73 6b } //02 00  screen_multi_task
		$a_01_4 = {61 70 69 2e 73 69 78 6d 69 73 73 2e 63 6f 6d } //00 00  api.sixmiss.com
	condition:
		any of ($a_*)
 
}