
rule PWS_Win32_Wowsteal_AR{
	meta:
		description = "PWS:Win32/Wowsteal.AR,SIGNATURE_TYPE_PEHSTR_EXT,20 00 1f 00 05 00 00 "
		
	strings :
		$a_01_0 = {77 74 66 5c 63 6f 6e 66 69 67 2e 77 74 66 } //10 wtf\config.wtf
		$a_00_1 = {25 73 3f 75 3d 25 73 26 61 3d 25 73 26 6d 3d 25 73 26 75 72 6c 3d 25 73 26 61 63 74 69 6f 6e 3d 25 73 } //10 %s?u=%s&a=%s&m=%s&url=%s&action=%s
		$a_00_2 = {77 6f 77 73 79 73 74 65 6d 63 6f 64 65 } //10 wowsystemcode
		$a_00_3 = {2f 67 65 74 2e 61 73 70 } //1 /get.asp
		$a_00_4 = {52 65 67 53 65 74 56 61 6c 75 65 45 78 28 73 74 61 72 74 29 } //1 RegSetValueEx(start)
	condition:
		((#a_01_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=31
 
}