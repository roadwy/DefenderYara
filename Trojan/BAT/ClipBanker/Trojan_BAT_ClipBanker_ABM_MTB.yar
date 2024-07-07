
rule Trojan_BAT_ClipBanker_ABM_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.ABM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 0b 00 00 "
		
	strings :
		$a_80_0 = {53 74 65 61 6c 65 72 } //Stealer  3
		$a_80_1 = {4b 65 79 56 61 6c 75 65 50 61 69 72 } //KeyValuePair  3
		$a_80_2 = {58 35 30 39 43 68 61 69 6e } //X509Chain  3
		$a_80_3 = {52 65 67 65 78 50 61 74 74 65 72 6e 73 } //RegexPatterns  3
		$a_80_4 = {43 6c 69 70 62 6f 61 72 64 4d 6f 6e 69 74 6f 72 } //ClipboardMonitor  3
		$a_80_5 = {63 6c 69 70 62 6f 61 72 64 5f 63 68 61 6e 67 65 64 } //clipboard_changed  3
		$a_80_6 = {72 65 70 6c 61 63 65 5f 63 6c 69 70 62 6f 61 72 64 } //replace_clipboard  3
		$a_80_7 = {41 75 74 6f 72 75 6e } //Autorun  3
		$a_80_8 = {69 73 5f 69 6e 73 74 61 6c 6c 65 64 } //is_installed  3
		$a_80_9 = {63 6c 69 70 62 6f 61 72 64 5f 63 68 65 63 6b 5f 64 65 6c 61 79 } //clipboard_check_delay  3
		$a_80_10 = {73 65 74 5f 68 69 64 64 65 6e } //set_hidden  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3+(#a_80_8  & 1)*3+(#a_80_9  & 1)*3+(#a_80_10  & 1)*3) >=33
 
}