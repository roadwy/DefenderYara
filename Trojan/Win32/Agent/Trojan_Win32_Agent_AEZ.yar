
rule Trojan_Win32_Agent_AEZ{
	meta:
		description = "Trojan:Win32/Agent.AEZ,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 20 75 20 6c 61 74 65 72 } //1 c u later
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {43 3a 5c 6b 65 72 6e 65 6c 63 68 65 63 6b 2e 65 78 65 } //1 C:\kernelcheck.exe
		$a_01_3 = {73 68 65 6c 6c 5c 41 75 74 6f 5c 63 6f 6d 6d 61 6e 64 3d 61 75 74 6f 72 75 6e 2e 65 78 65 } //1 shell\Auto\command=autorun.exe
		$a_01_4 = {6d 61 67 6e 65 74 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 magnet\shell\open\command
		$a_01_5 = {43 3a 5c 54 45 4d 50 5c 5c 73 79 73 66 6e 78 2e 65 78 65 } //1 C:\TEMP\\sysfnx.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}