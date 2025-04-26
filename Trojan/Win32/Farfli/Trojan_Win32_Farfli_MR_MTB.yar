
rule Trojan_Win32_Farfli_MR_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {52 65 73 53 6b 69 6e 2e 65 78 65 } //1 ResSkin.exe
		$a_01_1 = {4d 59 54 59 50 45 } //1 MYTYPE
		$a_01_2 = {54 00 52 00 41 00 43 00 4b 00 42 00 41 00 52 00 } //1 TRACKBAR
		$a_01_3 = {63 65 66 5f 62 72 6f 77 73 65 72 5f 68 6f 73 74 5f 63 72 65 61 74 65 5f 62 72 6f 77 73 65 72 5f 73 79 6e 63 } //1 cef_browser_host_create_browser_sync
		$a_01_4 = {63 65 66 5f 62 61 73 65 36 34 64 65 63 6f 64 65 } //1 cef_base64decode
		$a_01_5 = {63 65 66 5f 62 61 73 65 36 34 65 6e 63 6f 64 65 } //1 cef_base64encode
		$a_01_6 = {63 65 66 5f 67 65 74 5f 70 61 74 68 } //1 cef_get_path
		$a_01_7 = {63 65 66 5f 73 65 74 5f 63 72 61 73 68 5f 6b 65 79 5f 76 61 6c 75 65 } //1 cef_set_crash_key_value
		$a_01_8 = {63 65 66 5f 73 68 75 74 64 6f 77 6e } //1 cef_shutdown
		$a_01_9 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_01_10 = {47 65 74 4b 65 79 53 74 61 74 65 } //1 GetKeyState
		$a_01_11 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //1 UnhookWindowsHookEx
		$a_01_12 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //1 GetAsyncKeyState
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}