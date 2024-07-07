
rule Trojan_BAT_Clipper_AA_MTB{
	meta:
		description = "Trojan:BAT/Clipper.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {61 75 74 6f 72 75 6e 5f 65 6e 61 62 6c 65 64 } //1 autorun_enabled
		$a_01_1 = {43 6c 69 70 62 6f 61 72 64 4d 6f 6e 69 74 6f 72 } //1 ClipboardMonitor
		$a_01_2 = {72 65 70 6c 61 63 65 5f 63 6c 69 70 62 6f 61 72 64 } //1 replace_clipboard
		$a_01_3 = {41 70 70 4d 75 74 65 78 } //1 AppMutex
		$a_01_4 = {63 6c 69 70 62 6f 61 72 64 5f 63 68 65 63 6b 5f 64 65 6c 61 79 } //1 clipboard_check_delay
		$a_01_5 = {73 74 61 72 74 75 70 5f 64 69 72 65 63 74 6f 72 79 } //1 startup_directory
		$a_01_6 = {43 6c 69 70 70 65 72 } //1 Clipper
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}