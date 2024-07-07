
rule Trojan_AndroidOS_Ginp_A{
	meta:
		description = "Trojan:AndroidOS/Ginp.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {45 58 54 45 4e 44 45 44 5f 49 4e 4a 45 43 54 49 4f 4e } //1 EXTENDED_INJECTION
		$a_01_1 = {73 74 61 72 74 48 69 64 64 65 6e 53 4d 53 41 63 74 69 76 69 74 79 } //1 startHiddenSMSActivity
		$a_01_2 = {73 65 6e 64 49 6e 62 6f 78 4d 65 73 73 61 67 65 73 54 6f 53 65 72 76 65 72 } //1 sendInboxMessagesToServer
		$a_01_3 = {73 74 61 72 74 41 63 63 65 73 73 69 62 69 6c 69 74 79 57 61 74 63 68 65 72 } //1 startAccessibilityWatcher
		$a_01_4 = {48 49 44 45 5f 44 45 4c 41 59 5f 53 54 41 52 54 5f 57 49 4e 44 4f 57 } //1 HIDE_DELAY_START_WINDOW
		$a_01_5 = {44 45 42 55 47 5f 54 4f 5f 41 50 49 } //1 DEBUG_TO_API
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}