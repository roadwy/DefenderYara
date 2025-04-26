
rule TrojanSpy_Win32_Keylogger_EQ{
	meta:
		description = "TrojanSpy:Win32/Keylogger.EQ,SIGNATURE_TYPE_PEHSTR,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {69 6e 64 65 78 2e 70 68 70 3f 6d 73 67 3d 25 73 26 65 6d 61 69 6c 3d 25 73 26 66 72 6f 6d 3d 25 73 } //1 index.php?msg=%s&email=%s&from=%s
		$a_01_1 = {65 76 69 6c 63 6f 64 65 72 7a } //1 evilcoderz
		$a_01_2 = {6b 6c 68 6f 6f 6b } //1 klhook
		$a_01_3 = {3a 2a 3a 45 6e 61 62 6c 65 64 3a } //1 :*:Enabled:
		$a_01_4 = {53 59 53 54 45 4d 5c 43 6f 6e 74 72 6f 6c 53 65 74 30 30 31 5c 53 65 72 76 69 63 65 73 5c 53 68 61 72 65 64 41 63 63 65 73 73 5c 50 61 72 61 6d 65 74 65 72 73 5c 46 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79 5c 53 74 61 6e 64 61 72 64 50 72 6f 66 69 6c 65 5c 41 75 74 68 6f 72 69 7a 65 64 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 4c 69 73 74 } //1 SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\AuthorizedApplications\List
		$a_01_5 = {65 6e 74 65 72 } //1 enter
		$a_01_6 = {62 61 63 6b 73 70 61 63 65 } //1 backspace
		$a_01_7 = {69 6e 73 65 72 74 } //1 insert
		$a_01_8 = {73 63 72 6f 6c 6c 5f 6c 6f 63 6b } //1 scroll_lock
		$a_01_9 = {70 61 75 73 65 } //1 pause
		$a_01_10 = {70 72 6e 74 5f 73 63 72 6e } //1 prnt_scrn
		$a_01_11 = {63 61 70 73 5f 6c 6f 63 6b } //1 caps_lock
		$a_01_12 = {73 68 69 66 74 } //1 shift
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}