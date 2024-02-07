
rule Trojan_AndroidOS_SpyBanker_Q{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.Q,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {50 65 72 6d 69 73 53 63 72 65 65 6e } //02 00  PermisScreen
		$a_01_1 = {49 6e 74 65 72 6e 61 6c 43 61 6d 42 72 6f 77 73 65 72 53 63 72 65 65 6e } //02 00  InternalCamBrowserScreen
		$a_01_2 = {41 4d 53 55 6e 73 74 6f 70 61 62 6c 6c 65 } //00 00  AMSUnstopablle
	condition:
		any of ($a_*)
 
}