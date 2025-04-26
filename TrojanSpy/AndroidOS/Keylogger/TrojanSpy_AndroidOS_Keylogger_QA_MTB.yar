
rule TrojanSpy_AndroidOS_Keylogger_QA_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Keylogger.QA!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {76 6e 63 5f 6f 76 65 72 6c 61 79 5f 65 6e 61 62 6c 65 64 } //1 vnc_overlay_enabled
		$a_00_1 = {69 6e 6a 65 63 74 73 5f 6c 69 73 74 } //1 injects_list
		$a_00_2 = {6b 65 79 6c 6f 67 67 65 72 5f 65 6e 61 62 6c 65 64 } //1 keylogger_enabled
		$a_00_3 = {6c 61 73 74 5f 61 70 70 6c 69 73 74 5f 75 70 64 61 74 65 } //1 last_applist_update
		$a_00_4 = {45 6e 61 62 6c 65 20 53 4d 53 20 69 6e 74 65 72 63 65 70 74 } //1 Enable SMS intercept
		$a_00_5 = {43 52 41 53 48 20 4d 53 47 20 54 45 53 54 } //1 CRASH MSG TEST
		$a_00_6 = {68 69 64 65 49 63 6f 6e } //1 hideIcon
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}