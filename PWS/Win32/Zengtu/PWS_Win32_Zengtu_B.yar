
rule PWS_Win32_Zengtu_B{
	meta:
		description = "PWS:Win32/Zengtu.B,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 09 00 0b 00 00 02 00 "
		
	strings :
		$a_00_0 = {57 68 42 6f 79 } //02 00  WhBoy
		$a_00_1 = {5a 68 65 6e 67 54 75 } //02 00  ZhengTu
		$a_01_2 = {6d 61 69 6c 62 6f 64 79 3d } //02 00  mailbody=
		$a_00_3 = {60 75 75 70 32 2e 2e } //02 00  `uup2..
		$a_00_4 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a } //01 00  Content-Type:
		$a_01_5 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //01 00  CreateToolhelp32Snapshot
		$a_00_6 = {4d 75 74 65 78 } //01 00  Mutex
		$a_00_7 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_8 = {48 6f 6f 6b 4f 6e } //f1 ff  HookOn
		$a_00_9 = {67 67 73 61 66 65 2e 63 6f 6d 2f 67 67 74 6f 6f 6c 73 2e 69 6e 69 } //f1 ff  ggsafe.com/ggtools.ini
		$a_00_10 = {75 70 64 61 74 65 2e 67 67 73 61 66 65 2e 63 6f 6d 2f } //00 00  update.ggsafe.com/
	condition:
		any of ($a_*)
 
}