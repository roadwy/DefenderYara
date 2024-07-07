
rule Trojan_Win32_Agent_NAL{
	meta:
		description = "Trojan:Win32/Agent.NAL,SIGNATURE_TYPE_PEHSTR_EXT,24 00 24 00 0b 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //10 CreateToolhelp32Snapshot
		$a_01_1 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //10 WriteProcessMemory
		$a_01_2 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //10 CreateRemoteThread
		$a_00_3 = {64 65 6c 20 22 63 3a 5c 6d 79 61 70 70 2e 65 78 65 22 } //1 del "c:\myapp.exe"
		$a_00_4 = {70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 3e 6e 75 6c } //1 ping 127.0.0.1 >nul
		$a_00_5 = {69 66 20 65 78 69 73 74 20 22 63 3a 5c 6d 79 61 70 70 2e 65 78 65 } //1 if exist "c:\myapp.exe
		$a_00_6 = {22 20 67 6f 74 6f 20 74 72 79 } //1 " goto try
		$a_00_7 = {63 3a 5c 6d 79 44 65 6c 6d 2e 62 61 74 } //1 c:\myDelm.bat
		$a_01_8 = {33 36 30 74 72 61 79 2e 65 78 65 } //1 360tray.exe
		$a_01_9 = {4b 52 65 67 45 78 2e 65 78 65 } //1 KRegEx.exe
		$a_01_10 = {4b 56 58 50 2e 6b 78 70 } //1 KVXP.kxp
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=36
 
}