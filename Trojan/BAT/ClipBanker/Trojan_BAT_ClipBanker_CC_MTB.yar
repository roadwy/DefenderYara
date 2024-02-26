
rule Trojan_BAT_ClipBanker_CC_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {63 6c 69 70 62 6f 61 72 64 5f 63 68 65 63 6b 5f 64 65 6c 61 79 } //02 00  clipboard_check_delay
		$a_01_1 = {72 65 70 6c 61 63 65 5f 63 6c 69 70 62 6f 61 72 64 } //02 00  replace_clipboard
		$a_01_2 = {63 6c 69 70 62 6f 61 72 64 5f 63 68 61 6e 67 65 64 } //02 00  clipboard_changed
		$a_01_3 = {61 75 74 6f 72 75 6e 5f 65 6e 61 62 6c 65 64 } //02 00  autorun_enabled
		$a_01_4 = {61 75 74 6f 72 75 6e 5f 6e 61 6d 65 } //00 00  autorun_name
	condition:
		any of ($a_*)
 
}