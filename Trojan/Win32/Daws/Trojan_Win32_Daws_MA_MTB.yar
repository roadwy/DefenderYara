
rule Trojan_Win32_Daws_MA_MTB{
	meta:
		description = "Trojan:Win32/Daws.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 08 00 00 05 00 "
		
	strings :
		$a_03_0 = {89 c8 89 cf f7 e6 c1 ea 03 8d 04 92 01 c0 29 c7 0f b6 87 90 01 04 30 44 0d 00 83 c1 01 39 d9 75 90 00 } //02 00 
		$a_01_1 = {3a 5c 77 69 6e 64 6f 77 73 5c 74 61 73 6b 73 5c 77 69 6e 64 6f 77 73 2e 65 78 65 } //02 00  :\windows\tasks\windows.exe
		$a_01_2 = {73 6b 69 64 68 75 6e 74 65 72 } //02 00  skidhunter
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //02 00  SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
		$a_01_4 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 73 63 20 6d 69 6e 75 74 65 } //02 00  schtasks /create /sc minute
		$a_01_5 = {2f 72 75 20 73 79 73 74 65 6d } //01 00  /ru system
		$a_01_6 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  CheckRemoteDebuggerPresent
		$a_01_7 = {63 6c 6f 73 65 73 6f 63 6b 65 74 } //00 00  closesocket
	condition:
		any of ($a_*)
 
}