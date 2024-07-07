
rule MonitoringTool_Win32_XPCSpy{
	meta:
		description = "MonitoringTool:Win32/XPCSpy,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {58 50 43 53 70 79 20 50 72 6f 20 41 70 70 6c 69 63 61 74 69 6f 6e 20 4d 75 74 65 78 } //1 XPCSpy Pro Application Mutex
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_2 = {5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 68 65 6c 6c 50 61 74 68 } //1 \SOFTWARE\Microsoft\Windows\CurrentVersion\ShellPath
		$a_01_3 = {73 79 73 74 65 6d 69 6e 2e 73 79 73 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}