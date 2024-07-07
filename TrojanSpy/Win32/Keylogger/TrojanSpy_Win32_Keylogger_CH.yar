
rule TrojanSpy_Win32_Keylogger_CH{
	meta:
		description = "TrojanSpy:Win32/Keylogger.CH,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 64 6f 77 73 20 46 69 72 65 77 61 6c 6c 20 34 } //1 Windows Firewall 4
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {6b 65 79 6c 6f 67 67 65 72 } //1 keylogger
		$a_01_3 = {6c 6f 67 73 3d 75 70 64 61 74 65 3d } //1 logs=update=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}