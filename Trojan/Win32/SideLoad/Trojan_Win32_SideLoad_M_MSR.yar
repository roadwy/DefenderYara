
rule Trojan_Win32_SideLoad_M_MSR{
	meta:
		description = "Trojan:Win32/SideLoad.M!MSR,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {63 65 66 5f 73 68 75 74 64 6f 77 6e } //1 cef_shutdown
		$a_81_1 = {63 65 66 5f 70 6f 73 74 5f 74 61 73 6b } //1 cef_post_task
		$a_81_2 = {43 43 6d 64 54 61 72 67 65 74 } //1 CCmdTarget
		$a_81_3 = {45 6e 70 75 64 2e 70 6e 67 } //1 Enpud.png
		$a_81_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_81_5 = {4d 6f 6e 69 74 6f 72 46 72 6f 6d 57 69 6e 64 6f 77 } //1 MonitorFromWindow
		$a_81_6 = {4d 6f 6e 69 74 6f 72 46 72 6f 6d 52 65 63 74 } //1 MonitorFromRect
		$a_81_7 = {4d 6f 6e 69 74 6f 72 46 72 6f 6d 50 6f 69 6e 74 } //1 MonitorFromPoint
		$a_81_8 = {45 6e 75 6d 44 69 73 70 6c 61 79 4d 6f 6e 69 74 6f 72 73 } //1 EnumDisplayMonitors
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}